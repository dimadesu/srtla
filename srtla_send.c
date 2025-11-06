/*
    srtla - SRT transport proxy with link aggregation
    Copyright (C) 2020-2021 BELABOX project

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "android_compat.h"  // Android compatibility layer

#define PKT_LOG_SZ 256
#define CONN_TIMEOUT 4
#define REG2_TIMEOUT 4
#define REG3_TIMEOUT 4
#define GLOBAL_TIMEOUT 10
#define IDLE_TIME 1

#define SEND_BUF_SIZE (8 * 1024 * 1024)

#define min(a, b) ((a < b) ? a : b)
#define max(a, b) ((a > b) ? a : b)
#define min_max(a, l, h) (max(min((a), (h)), (l)))

#define WINDOW_MIN 1
#define WINDOW_DEF 20
#define WINDOW_MAX 60
#define WINDOW_MULT 1000
#define WINDOW_DECR 100
#define WINDOW_INCR 30

#define LOG_PKT_INT 20

// Bitrate calculation constants
#define BITRATE_UPDATE_INTERVAL_SECONDS 2  // Update bitrate every 2 seconds (matching Java)

#ifdef ANDROID
typedef enum {
    NETWORK_TYPE_UNKNOWN = 0,
    NETWORK_TYPE_WIFI = 1,
    NETWORK_TYPE_CELLULAR = 2
} network_type_t;
#endif

typedef struct conn {
  struct conn *next;
  int fd;
  time_t last_rcvd;
  time_t last_sent;
  struct sockaddr src;       // Virtual address for SRTLA's internal use
#ifdef ANDROID
  struct sockaddr real_src;  // Real network address for actual I/O
  network_type_t network_type;
  char virtual_ip[16];
  char real_ip[16];
#endif
  int removed;
  int in_flight_pkts;
  int window;
  int pkt_idx;
  int pkt_log[PKT_LOG_SZ];
  // Bitrate tracking (matching Java implementation)
  uint64_t bytes_sent_total;
  uint64_t bytes_sent_window;  // Last bytes snapshot for difference calculation
  time_t last_rate_update;     // Last time we updated the rate measurement
  double current_bitrate_bps;  // Current bitrate in bits per second
} conn_t;

// Forward declaration for bitrate functions
static void update_connection_bitrate(conn_t *c, uint64_t bytes_sent);
static void update_individual_connection_bitrate(conn_t *c);
static double calculate_total_bitrate(void);
static int calculate_connection_load_percentage(conn_t *c);

char *source_ip_file = NULL;

#ifdef ANDROID
// Global stop flag for Android - allows graceful shutdown
static volatile int srtla_should_stop = 0;

// Global flags for Android
#ifdef __ANDROID__
int srtla_should_exit = 0;
int srtla_exit_code = 0;
#endif

// Virtual IP definitions for Application-Level Virtual IPs
#define VIRTUAL_IP_WIFI     "10.0.1.1"
#define VIRTUAL_IP_CELLULAR "10.0.2.1" 
#define VIRTUAL_IP_PREFIX   "10.0."

typedef struct virtual_conn {
    char virtual_ip[16];          // e.g., "10.0.1.1"
    char real_ip[16];            // e.g., "172.20.10.2"  
    network_type_t network_type; // WIFI or CELLULAR
    int socket_fd;               // Pre-bound network socket from Android
    struct sockaddr real_addr;   // Real network address
    struct virtual_conn *next;
} virtual_conn_t;

static virtual_conn_t *virtual_connections = NULL;
#endif

int do_update_conns = 0;

struct addrinfo *addrs;

#ifdef ANDROID
// Virtual IP management functions

// Add a virtual connection mapping
int add_virtual_connection(const char* virtual_ip, const char* real_ip, 
                          network_type_t type, int socket_fd) {
    virtual_conn_t *vc = malloc(sizeof(virtual_conn_t));
    if (!vc) return -1;
    
    memset(vc, 0, sizeof(virtual_conn_t));
    strncpy(vc->virtual_ip, virtual_ip, sizeof(vc->virtual_ip)-1);
    strncpy(vc->real_ip, real_ip, sizeof(vc->real_ip)-1);
    vc->network_type = type;
    vc->socket_fd = socket_fd;
    
    // Parse real IP into sockaddr
    struct sockaddr_in *addr = (struct sockaddr_in*)&vc->real_addr;
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, real_ip, &addr->sin_addr) != 1) {
        free(vc);
        return -1;
    }
    addr->sin_port = htons(0);
    
    // Add to linked list
    vc->next = virtual_connections;
    virtual_connections = vc;
    
    info("Added virtual connection: %s -> %s (type=%d, fd=%d)\n", 
         virtual_ip, real_ip, type, socket_fd);
    return 0;
}

// Find virtual connection by virtual IP
virtual_conn_t* find_virtual_connection(const char* virtual_ip) {
    for (virtual_conn_t *vc = virtual_connections; vc != NULL; vc = vc->next) {
        if (strcmp(vc->virtual_ip, virtual_ip) == 0) {
            return vc;
        }
    }
    return NULL;
}

// Check if IP is in virtual range
int is_virtual_ip(const char* ip) {
    return strncmp(ip, VIRTUAL_IP_PREFIX, strlen(VIRTUAL_IP_PREFIX)) == 0;
}

// Convert real IP to virtual IP for SRTLA's internal use
const char* real_to_virtual_ip(const char* real_ip) {
    for (virtual_conn_t *vc = virtual_connections; vc != NULL; vc = vc->next) {
        if (strcmp(vc->real_ip, real_ip) == 0) {
            return vc->virtual_ip;
        }
    }
    return real_ip; // Fallback to real IP if no mapping found
}

// Get routing address (real address for network I/O)
struct sockaddr* get_routing_address(conn_t *c) {
#ifdef ANDROID
    if (strlen(c->virtual_ip) > 0) {
        return &c->real_src;  // Use real address for actual network I/O
    }
#endif
    return &c->src;  // Use original address for non-virtual
}

// JNI function to receive pre-bound socket from Android
void srtla_set_network_socket(const char* virtual_ip, const char* real_ip, 
                             int network_type, int socket_fd) {
    add_virtual_connection(virtual_ip, real_ip, (network_type_t)network_type, socket_fd);
}
#endif

struct sockaddr srtla_addr, srt_addr;
const socklen_t addr_len = sizeof(srtla_addr);
conn_t *conns = NULL;
int listenfd;
int active_connections = 0;
int has_connected = 0;

conn_t *pending_reg2_conn = NULL;
time_t pending_reg_timeout = 0;

char srtla_id[SRTLA_ID_LEN];


/*

Async I/O support

*/
fd_set active_fds;
int max_act_fd = -1;

int add_active_fd(int fd) {
  if (fd < 0) return -1;

  if (fd > max_act_fd) max_act_fd = fd;
  FD_SET(fd, &active_fds);

  return 0;
}

int remove_active_fd(int fd) {
  if (fd < 0) return -1;

  FD_CLR(fd, &active_fds);

  return 0;
}


/*

Misc helper functions

*/
void print_help() {
  fprintf(stderr,
          "Syntax: srtla_send SRT_LISTEN_PORT SRTLA_HOST SRTLA_PORT BIND_IPS_FILE\n\n"
          "-v      Print the version and exit\n");
}


/*

srtla registration helpers

*/
int send_reg1(conn_t *c) {
  if (c->fd < 0) return -1;

  char buf[MTU];
  uint16_t packet_type = htobe16(SRTLA_TYPE_REG1);
  memcpy(buf, &packet_type, sizeof(packet_type));
  memcpy(buf + sizeof(packet_type), srtla_id, SRTLA_ID_LEN);

  int ret = sendto(c->fd, buf, SRTLA_TYPE_REG1_LEN, 0, &srtla_addr, addr_len);
  if (ret != SRTLA_TYPE_REG1_LEN) return -1;

  return 0;
}

int send_reg2(conn_t *c) {
  if (c->fd < 0) return -1;

  char buf[SRTLA_TYPE_REG2_LEN];
  uint16_t packet_type = htobe16(SRTLA_TYPE_REG2);
  memcpy(buf, &packet_type, sizeof(packet_type));
  memcpy(buf + sizeof(packet_type), srtla_id, SRTLA_ID_LEN);

  int ret = sendto(c->fd, buf, SRTLA_TYPE_REG2_LEN, 0, &srtla_addr, addr_len);
  return (ret == SRTLA_TYPE_REG2_LEN) ? 0 : -1;
}


/*

Handling code for packets coming from the SRT caller

*/
void reg_pkt(conn_t *c, int32_t packet) {
  debug("%s (%p): register packet %d at idx %d\n",
        print_addr(&c->src), c, packet, c->pkt_idx);
  c->pkt_log[c->pkt_idx] = packet;
  c->pkt_idx++;
  c->pkt_idx %= PKT_LOG_SZ;

  c->in_flight_pkts++;
}

int conn_timed_out(conn_t *c, time_t ts) {
  return (c->last_rcvd + CONN_TIMEOUT) < ts;
}

conn_t *select_conn() {
  conn_t *min_c = NULL;
  int max_score = -1;
  int max_window = 0;

  for (conn_t *c = conns; c != NULL; c = c->next) {
    if (c->window > max_window) {
      max_window = c->window;
    }
  }

  time_t t;
  assert(get_seconds(&t) == 0);

  for (conn_t *c = conns; c != NULL; c = c->next) {
    /* If we have some very slow links, we may be better off ignoring them
       However, we'd probably need to periodically re-probe them, otherwise
       a link disabled due to a momentary glitch might not ever get enabled
       again unless all the remaining links suffered from high packet loss
       at some point. */
    /*if (c->window < max_window / 5) {
      c->window++;
      continue;
    }*/

    if (conn_timed_out(c, t)) {
      debug("%s (%p): is timed out, ignoring it\n", print_addr(&c->src), c);
      continue;
    }

    int score = c->window / (c->in_flight_pkts + 1);
    if (score > max_score) {
      min_c = c;
      max_score = score;
    }
  }

  if (min_c) {
    min_c->last_sent = t;
  }

  return min_c;
}

void handle_srt_data(int fd) {
  char buf[MTU];
  socklen_t len = sizeof(srt_addr);
  int n = recvfrom(fd, &buf, MTU, 0, &srt_addr, &len);

  conn_t *c = select_conn();
  if (c) {
    int32_t sn = get_srt_sn(buf, n);
    int ret = sendto(c->fd, &buf, n, 0, &srtla_addr, addr_len);
    if (ret == n) {
      // Track bytes sent for bitrate calculation
      update_connection_bitrate(c, n);
      
      if (sn >= 0) {
        reg_pkt(c, sn);
      }
    } else {
      /* If sending the packet fails, adjust the timestamp to disable the link until a
         reconnection is confirmed. 1 so connection_housekeeping() prints its message */
      c->last_rcvd = 1;
      err("%s (%p): sendto() failed, disabling the connection\n",
          print_addr(&c->src), c);
    }
  }
}


/*

Handling code for packets coming from the receiver

*/
int get_pkt_idx(int idx, int increment) {
  idx = idx + increment;
  if (idx < 0) idx += PKT_LOG_SZ;
  idx %= PKT_LOG_SZ;
  assert(idx >= 0 && idx < PKT_LOG_SZ);
  return idx;
}

void register_nak(int32_t packet) {
  for (conn_t *c = conns; c != NULL; c = c->next) {
    int idx = get_pkt_idx(c->pkt_idx, -1);
    for (int i = idx; i != c->pkt_idx; i = get_pkt_idx(i, -1)) {
      if (c->pkt_log[i] == packet) {
        c->pkt_log[i] = -1;
        // It might be better to use exponential decay like this
        //c->window = c->window * 998 / 1000;
        c->window -= WINDOW_DECR;
        c->window = max(c->window, WINDOW_MIN*WINDOW_MULT);
        debug("%s (%p): found NAKed packet %d in the log\n",
              print_addr(&c->src), c, packet);
        return;
      }
    }
  }

  debug("Didn't find NAKed packet %d in our logs\n", packet);
}

void register_srtla_ack(int32_t ack) {
  int found = 0;

  for (conn_t *c = conns; c != NULL; c = c->next) {
    int idx = get_pkt_idx(c->pkt_idx, -1);
    for (int i = idx; i != c->pkt_idx && !found; i = get_pkt_idx(i, -1)) {
      if (c->pkt_log[i] == ack) {
        found = 1;
        if (c->in_flight_pkts > 0) {
          c->in_flight_pkts--;
        }
        c->pkt_log[i] = -1;

        if (c->in_flight_pkts*WINDOW_MULT > c->window) {
          c->window += WINDOW_INCR - 1;
        }

        break;
      }
    }

    if (c->last_rcvd != 0) {
      c->window += 1;
      c->window = min(c->window, WINDOW_MAX*WINDOW_MULT);
    }
  }
}

/*
  TODO after the sequence number overflows, we should probably also mark high
  sn packets as received. However, this shouldn't normally be an issue as SRTLA
  ACKs acknowledge each packet individually. Also, if the SRTLA ACK is lost,
  stale entries will be overwritten soon enough as pkt_log is a circular buffer
*/
void conn_register_srt_ack(conn_t *c, int32_t ack) {
  int count = 0;
  int idx = get_pkt_idx(c->pkt_idx, -1);
  for (int i = idx; i != c->pkt_idx; i = get_pkt_idx(i, -1)) {
    if (c->pkt_log[i] < ack) {
      c->pkt_log[i] = -1;
    } else {
      count++;
    }
  }
  c->in_flight_pkts = count;
}

void register_srt_ack(int32_t ack) {
  for (conn_t *c = conns; c != NULL; c = c->next) {
    conn_register_srt_ack(c, ack);
  }
}

void handle_srtla_data(conn_t *c) {
  char buf[MTU];

  int n = recvfrom(c->fd, &buf, MTU, 0, NULL, NULL);
  if (n <= 0) return;

  time_t ts;
  get_seconds(&ts);

  uint16_t packet_type = get_srt_type(buf, n);

  /* Handling NGPs separately because we don't want them to update last_rcvd
     Otherwise they could be keeping failed connections marked active */
  if (packet_type == SRTLA_TYPE_REG_NGP) {
    /* Only process NGPs if:
       * we don't have any established connections
       * and we don't already have a pending REG1->REG2 exhange in flight
       * and we don't have any pending REG2->REG3 exchanges in flight
    */
    if (active_connections == 0 && pending_reg2_conn == NULL && ts > pending_reg_timeout) {
      if (send_reg1(c) == 0) {
        pending_reg2_conn = c;
        pending_reg_timeout = ts + REG2_TIMEOUT;
      }
    }
    return;

  } else if (packet_type == SRTLA_TYPE_REG2) {
    if (pending_reg2_conn == c) {
      char *id = &buf[2];
      if (memcmp(id, srtla_id, SRTLA_ID_LEN/2) != 0) {
        err("%s (%p): got a mismatching ID in SRTLA_REG2\n",
           print_addr(&c->src), c);
        return;
      }

      info("%s (%p): connection group registered\n", print_addr(&c->src), c);
      memcpy(srtla_id, id, SRTLA_ID_LEN);

      /* Broadcast REG2 */
      for (conn_t *i = conns; i != NULL; i = i->next) {
        send_reg2(i);
      }

      pending_reg2_conn = NULL;
      pending_reg_timeout = ts + REG3_TIMEOUT;
    }
    return;
  }

  c->last_rcvd = ts;

  switch(packet_type) {
    case SRT_TYPE_ACK: {
      uint32_t last_ack = *((uint32_t *)&buf[16]);
      last_ack = be32toh(last_ack);
      register_srt_ack(last_ack);
      break;
    }

    case SRT_TYPE_NAK: {
      uint32_t *ids = (uint32_t *)buf;
      for (int i = 4; i < n/4; i++) {
        uint32_t id = be32toh(ids[i]);
        if (id & (1 << 31)) {
          id = id & 0x7FFFFFFF;
          uint32_t last_id = be32toh(ids[i+1]);
          for (int32_t lost = id; lost <= last_id; lost++) {
            register_nak(lost);
          }
          i++;
        } else {
          register_nak(id);
        }
      }
      break;
    }

    // srtla packets below, don't send to SRT
    case SRTLA_TYPE_ACK: {
      uint32_t *acks = (uint32_t *)buf;
      for (int i = 1; i < n/4; i++) {
        uint32_t id = be32toh(acks[i]);
        debug("%s (%p): ack %d\n", print_addr(&c->src), c, id);
        register_srtla_ack(id);
      }
      return;
    }
    case SRTLA_TYPE_KEEPALIVE:
      debug("%s (%p): got a keepalive\n", print_addr(&c->src), c);
      return; // don't send to SRT

    case SRTLA_TYPE_REG3:
      has_connected = 1;
      active_connections++;
      info("%s (%p): connection established\n", print_addr(&c->src), c);
#ifdef ANDROID
      // Call the JNI callback to notify that connection is established
      extern void srtla_on_connection_established(void);
      srtla_on_connection_established();
#endif
      return;
  } // switch

  sendto(listenfd, &buf, n, 0, &srt_addr, addr_len);
}


/*

Connection and socket management

*/
conn_t *conn_find_by_src(struct sockaddr *src) {
  for (conn_t *c = conns; c != NULL; c = c->next) {
    if (memcmp(src, &c->src, sizeof(*src)) == 0) {
      return c;
    }
  }

  return NULL;
}

int setup_conns(char *source_ip_file) {
  printf("Opening IP file: %s\n", source_ip_file);
  FILE *config = fopen(source_ip_file, "r");
  if (config == NULL) {
    printf("Failed to open the source ip list file: %s\n", source_ip_file);
    perror("Error details");
    exit_help();
  }

  int count = 0;
  char *line = NULL;
  size_t line_len = 0;
  while(getline(&line, &line_len, config) >= 0) {
    char *nl;
    if ((nl = strchr(line, '\n'))) {
      *nl = '\0';
    }

    printf("Parsing IP line: '%s'\n", line);
    struct sockaddr src;

    int ret = parse_ip((struct sockaddr_in *)&src, line);
    if (ret == 0) {
      printf("Successfully parsed IP: %s\n", line);
      conn_t *c = conn_find_by_src(&src);
      if (c == NULL) {
        conn_t *c = calloc(1, sizeof(conn_t));
        assert(c != NULL);

        c->src = src;
        c->fd = -1;
        c->window = WINDOW_DEF * WINDOW_MULT;
        
        // Initialize bitrate tracking
        c->bytes_sent_total = 0;
        c->bytes_sent_window = 0;
        c->last_rate_update = time(NULL);

#ifdef ANDROID
        // Check if this is a virtual IP
        if (is_virtual_ip(line)) {
          strncpy(c->virtual_ip, line, sizeof(c->virtual_ip)-1);
          printf("Configured virtual IP: %s\n", c->virtual_ip);
        } else {
          c->virtual_ip[0] = '\0';  // Clear virtual IP for real IPs
        }
#endif

        c->next = conns;
        conns = c;

        count++;

        printf("Added connection via %s (%p)\n", print_addr(&c->src), c);
      } else {
        c->removed = 0;
      }
    } else {
      printf("Failed to parse IP: '%s' (error: %d)\n", line, ret);
    }
  }
  if (line) free(line);

  fclose(config);

  return count;
}

void update_conns(char *source_ip_file) {
  for (conn_t *c = conns; c != NULL; c = c->next) {
    c->removed = 1;
  }

  setup_conns(source_ip_file);

  conn_t **prev = &conns;
  conn_t *next;
  for (conn_t *c = conns; c != NULL; c = next) {
    next = c->next;
    if (c->removed) {
      printf("Removed connection via %s (%p)\n", print_addr(&c->src), c);

      if (c == pending_reg2_conn) {
        pending_reg2_conn = NULL;
      }

      remove_active_fd(c->fd);
      close(c->fd);
      *prev = c->next;
      free(c);
    } else {
      prev = &c->next;
    }
  }
}

void schedule_update_conns(int signal) {
  do_update_conns = 1;
}

int open_socket(conn_t *c, int quiet) {
  if (c->fd >= 0) {
    remove_active_fd(c->fd);
    close(c->fd);
    c->fd = -1;
  }

#ifdef ANDROID
  // For Android with virtual IPs, use pre-bound network socket
  if (strlen(c->virtual_ip) > 0) {
    virtual_conn_t *vc = find_virtual_connection(c->virtual_ip);
    if (vc && vc->socket_fd >= 0) {
      c->fd = vc->socket_fd;
      c->network_type = vc->network_type;
      memcpy(&c->real_src, &vc->real_addr, sizeof(c->real_src));
      strncpy(c->real_ip, vc->real_ip, sizeof(c->real_ip)-1);
      
      add_active_fd(c->fd);
      
      info("Using pre-bound socket for virtual IP %s -> real IP %s (fd=%d)\n", 
           c->virtual_ip, c->real_ip, c->fd);
      return 0;
    } else {
      if (!quiet) {
        err("No pre-bound socket found for virtual IP %s\n", c->virtual_ip);
      }
      return -1;
    }
  }
#endif

  // Fallback to original socket creation for non-Android or non-virtual IPs
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
  if (fd < 0) {
    err("Failed to open a socket");
    return -1;
  }

  int bufsize = SEND_BUF_SIZE;
  int ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
  if (ret != 0) {
    err("failed to set send buffer size (%d)\n", bufsize);
    goto err;
  }

  // Bind it to the source address
  ret = bind(fd, &c->src, sizeof(c->src));
  if (ret != 0) {
    if (!quiet) {
      err("Failed to bind to the source address %s\n", print_addr(&c->src));
    }
    goto err;
  }

  add_active_fd(fd);
  c->fd = fd;

  return 0;

err:
  close(fd);
  return -1;
}

int open_conns(char *host, char *port) {
  // Check that we can actually open & bind at least one socket
  int opened = 0;
  for (conn_t *c = conns; c != NULL; c = c->next) {
    if (open_socket(c, 0) == 0) {
      opened++;
    }
  }
  return opened;
}

/*

Connection housekeeping

*/
void set_srtla_addr(struct addrinfo *addr) {
  memcpy(&srtla_addr, addr->ai_addr, addr->ai_addrlen);
  info("Trying to connect to %s...\n", print_addr(&srtla_addr));
}

void send_keepalive(conn_t *c) {
  debug("%s (%p): sending keepalive\n", print_addr(&c->src), c);
  uint16_t pkt = htobe16(SRTLA_TYPE_KEEPALIVE);
  // ignoring the result on purpose
  sendto(c->fd, &pkt, sizeof(pkt), 0, &srtla_addr, addr_len);
}

#define HOUSEKEEPING_INT 1000 // ms
void connection_housekeeping() {
  static uint64_t all_failed_at = 0;
  /* We use milliseconds here because with a seconds timer we may be
     resending a second REG2 very soon after the first one, depending
     on when the first execution happens within the seconds interval */
  static uint64_t last_ran = 0;
  uint64_t ms;
  assert(get_ms(&ms) == 0);
  if ((last_ran + HOUSEKEEPING_INT) > ms) return;

  time_t time = (time_t)(ms / 1000);

  active_connections = 0;

  if (pending_reg2_conn && time > pending_reg_timeout) {
    pending_reg2_conn = NULL;
  }

  for (conn_t *c = conns; c != NULL; c = c->next) {
    if (c->fd < 0) {
      open_socket(c, 1);
      continue;
    }

    if (conn_timed_out(c, time)) {
      /* When we first detect the connection having failed,
         we reset its status and print a message */
      if (c->last_rcvd > 0) {
        info("%s (%p): connection failed, attempting to reconnect\n",
             print_addr(&c->src), c);
        c->last_rcvd = 0;
        c->last_sent = 0;
        c->window = WINDOW_MIN * WINDOW_MULT;
        c->in_flight_pkts = 0;
        for (int i = 0; i < PKT_LOG_SZ; i++) {
          c->pkt_log[i] = -1;
        }
      }

      if (pending_reg2_conn == NULL) {
        /* As the connection has timed out on our end, the receiver might have garbage
           collected it. Try to re-establish it rather than send a keepalive */
        send_reg2(c);
      } else if (pending_reg2_conn == c) {
        send_reg1(c);
      }
      continue;
    }

    /* If a connection has received data in the last CONN_TIMEOUT seconds,
       then it's active */
    active_connections++;

    if ((c->last_sent + IDLE_TIME) < time) {
      send_keepalive(c);
    }
  }

  if (active_connections == 0) {
    if (all_failed_at == 0) {
      all_failed_at = ms;
    }

    if (has_connected) {
      err("warning: no available connections\n");
    }

    // Timeout when all connections have failed
    if (ms > (all_failed_at + (GLOBAL_TIMEOUT * 1000))) {
      if (has_connected) {
        err("Failed to re-establish any connections to %s\n",
            print_addr(&srtla_addr));
        #ifdef __ANDROID__
        // Return with error code instead of exit for Android
        srtla_should_exit = 1;
        srtla_exit_code = EXIT_FAILURE;
        return;
        #else
        exit(EXIT_FAILURE);
        #endif
      }

      err("Failed to establish any initial connections to %s\n",
          print_addr(&srtla_addr));

      // Walk through the list of resolved addresses
      if (addrs->ai_next) {
        addrs = addrs->ai_next;
        set_srtla_addr(addrs);
        all_failed_at = 0;
      } else {
        #ifdef __ANDROID__
        // Return with error code instead of exit for Android
        srtla_should_exit = 1;
        srtla_exit_code = EXIT_FAILURE;
        return;
        #else
        exit(EXIT_FAILURE);
        #endif
      }
    }
  } else {
    all_failed_at = 0;
  }

  last_ran = ms;
}

#define ARG_LISTEN_PORT (argv[1])
#define ARG_SRTLA_HOST  (argv[2])
#define ARG_SRTLA_PORT  (argv[3])
#define ARG_IPS_FILE    (argv[4])
int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "-v") == 0) {
    printf(VERSION "\n");
    exit(0);
  }
  if (argc != 5) exit_help();

  source_ip_file = ARG_IPS_FILE;
  int conn_count = setup_conns(source_ip_file);
  if (conn_count <= 0) {
    fprintf(stderr, "Failed to parse any IP addresses in %s\n", source_ip_file);
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in listen_addr;

  int port = parse_port(ARG_LISTEN_PORT);
  if (port < 0) exit_help();

  // Read a random connection group id for this session
  FILE *fd = fopen("/dev/urandom", "rb");
  assert(fd != NULL);
  assert(fread(srtla_id, 1, SRTLA_ID_LEN, fd) == SRTLA_ID_LEN);
  fclose(fd);

  FD_ZERO(&active_fds);

  listen_addr.sin_family = AF_INET;
  listen_addr.sin_addr.s_addr = INADDR_ANY;
  listen_addr.sin_port = htons(port);
  listenfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (listenfd < 0) { 
    perror("socket creation failed"); 
    exit(EXIT_FAILURE); 
  }

  int ret = bind(listenfd, (struct sockaddr *)&listen_addr, sizeof(listen_addr));
  if (ret < 0) { 
    perror("bind failed"); 
    exit(EXIT_FAILURE); 
  }
  add_active_fd(listenfd);

  int connected = open_conns(ARG_SRTLA_HOST, ARG_SRTLA_PORT);
  if (connected < 1) {
    err("Failed to open and bind to any of the IP addresses in %s\n", source_ip_file);
    exit(EXIT_FAILURE);
  }

  // Resolve the address of the receiver
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  ret = getaddrinfo(ARG_SRTLA_HOST, ARG_SRTLA_PORT, &hints, &addrs);
  if (ret != 0) {
    err("Failed to resolve %s: %s\n", ARG_SRTLA_HOST, gai_strerror(ret));
    exit(EXIT_FAILURE);
  }

  set_srtla_addr(addrs);

  signal(SIGHUP, schedule_update_conns);

  int info_int = LOG_PKT_INT;

  while(1) {
    if (do_update_conns) {
      update_conns(source_ip_file);
      do_update_conns = 0;
    }

    connection_housekeeping();

    fd_set read_fds = active_fds;
    struct timeval to = {.tv_sec = 0, .tv_usec = 200*1000};
    ret = select(FD_SETSIZE, &read_fds, NULL, NULL, &to);

    if (ret > 0) {
      if (FD_ISSET(listenfd, &read_fds)) {
        handle_srt_data(listenfd);
      }

      for (conn_t *c = conns; c != NULL; c = c->next) {
        if (c->fd >= 0 && FD_ISSET(c->fd, &read_fds)) {
          handle_srtla_data(c);
        }
      }
    } // ret > 0

    info_int--;
    if (info_int == 0) {
      for (conn_t *c = conns; c != NULL; c = c->next) {
        debug("%s (%p): in flight: %d, window: %d, last_rcvd %ld\n",
              print_addr(&c->src), c, c->in_flight_pkts, c->window, c->last_rcvd);
      }
      info_int = LOG_PKT_INT;
    }
  } // while(1);
}

#ifdef ANDROID
/*
 * Android-compatible random number generation
 * Fallback if /dev/urandom is not accessible
 */
static int android_get_random(void *buf, size_t len) {
  FILE *fd = fopen("/dev/urandom", "rb");
  if (fd != NULL) {
    size_t result = fread(buf, 1, len, fd);
    fclose(fd);
    if (result == len) return 0;
  }
  
  // Fallback: use time-based seed (less secure but functional)
  srand((unsigned int)time(NULL));
  unsigned char *bytes = (unsigned char *)buf;
  for (size_t i = 0; i < len; i++) {
    bytes[i] = rand() & 0xFF;
  }
  return 0;
}

/*
 * Android stop function - sets stop flag for graceful shutdown
 */
void srtla_stop_android(void) {
  srtla_should_stop = 1;
}

/*
 * Android JNI entry point - preserves all original SRTLA functionality
 * This is identical to main() but callable from JNI
 */
int srtla_start_android(const char* listen_port, const char* srtla_host, 
                       const char* srtla_port, const char* ips_file) {
  
  // Reset stop flag
  srtla_should_stop = 0;
  
  // Clear any existing connections from previous runs
  while (conns != NULL) {
    conn_t *next = conns->next;
    if (conns->fd >= 0) {
      close(conns->fd);
    }
    free(conns);
    conns = next;
  }
  conns = NULL;  // Explicitly ensure it's NULL
  printf("Cleared existing connections for fresh start\n");
  
  source_ip_file = (char*)ips_file;  // Cast away const for compatibility
  printf("About to setup connections from file: %s\n", source_ip_file);
  int conn_count = setup_conns(source_ip_file);
  printf("setup_conns returned: %d connections\n", conn_count);
  if (conn_count <= 0) {
    printf("Failed to parse any IP addresses in %s\n", source_ip_file);
    return -1;  // Return error instead of exit()
  }
  printf("Successfully set up %d connections\n", conn_count);

  struct sockaddr_in listen_addr;

  int port = parse_port((char*)listen_port);  // Cast for compatibility
  if (port < 0) {
    printf("Invalid listen port: %s\n", listen_port);
    return -1;
  }

  // Android-compatible random ID generation
  if (android_get_random(srtla_id, SRTLA_ID_LEN) != 0) {
    printf("Failed to generate random session ID\n");
    return -1;
  }

  FD_ZERO(&active_fds);

  listen_addr.sin_family = AF_INET;
  listen_addr.sin_addr.s_addr = INADDR_ANY;
  listen_addr.sin_port = htons(port);
  listenfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (listenfd < 0) { 
    printf("socket creation failed\n");
    return -1;
  }

  // Enable socket reuse to allow binding to the same port immediately after restart
  int reuse = 1;
  if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    printf("setsockopt SO_REUSEADDR failed\n");
  }

  int ret = bind(listenfd, (struct sockaddr *)&listen_addr, sizeof(listen_addr));
  if (ret < 0) { 
    printf("bind failed\n");
    return -1;
  }
  add_active_fd(listenfd);

  int connected = open_conns((char*)srtla_host, (char*)srtla_port);  // Cast for compatibility
  if (connected < 1) {
    printf("Failed to open and bind to any of the IP addresses in %s\n", source_ip_file);
    return -1;
  }

  // Resolve the address of the receiver
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  ret = getaddrinfo(srtla_host, srtla_port, &hints, &addrs);
  if (ret != 0) {
    printf("Failed to resolve %s: %s\n", srtla_host, gai_strerror(ret));
    return -1;
  }

  set_srtla_addr(addrs);

  // Skip signal handler setup on Android - not needed for JNI
  // signal(SIGHUP, schedule_update_conns);

  int info_int = LOG_PKT_INT;

  // Main SRTLA loop - with stop flag check for Android
  while(!srtla_should_stop) {
    if (do_update_conns) {
      update_conns(source_ip_file);
      do_update_conns = 0;
    }

    connection_housekeeping();

    fd_set read_fds = active_fds;
    struct timeval to = {.tv_sec = 0, .tv_usec = 200*1000};
    ret = select(FD_SETSIZE, &read_fds, NULL, NULL, &to);

    if (ret > 0) {
      if (FD_ISSET(listenfd, &read_fds)) {
        handle_srt_data(listenfd);
      }

      for (conn_t *c = conns; c != NULL; c = c->next) {
        if (c->fd >= 0 && FD_ISSET(c->fd, &read_fds)) {
          handle_srtla_data(c);
        }
      }
    }

    info_int--;
    if (info_int == 0) {
      for (conn_t *c = conns; c != NULL; c = c->next) {
        debug("%s (%p): in flight: %d, window: %d, last_rcvd %ld\n",
              print_addr(&c->src), c, c->in_flight_pkts, c->window, c->last_rcvd);
      }
      info_int = LOG_PKT_INT;
    }
  }
  
  return 0;  // Should never reach here due to while(1)
}

/*
 * Android stats functions - minimal stats for UI
 */
int srtla_get_connection_count(void) {
  int count = 0;
  for (conn_t *c = conns; c != NULL; c = c->next) {
    if (!c->removed) {
      count++;
    }
  }
  return count;
}

int srtla_get_active_connection_count(void) {
  int count = 0;
  time_t now = time(NULL);
  for (conn_t *c = conns; c != NULL; c = c->next) {
    if (c->removed) continue;
    // Consider a connection active if it received data in the last 5 seconds
    if ((now - c->last_rcvd) <= 5) {
      count++;
    }
  }
  return count;
}

int srtla_get_total_in_flight_packets(void) {
  int total = 0;
  for (conn_t *c = conns; c != NULL; c = c->next) {
    if (c->removed) continue;
    total += c->in_flight_pkts;
  }
  return total;
}

int srtla_get_total_window_size(void) {
  int total = 0;
  for (conn_t *c = conns; c != NULL; c = c->next) {
    if (c->removed) continue;
    total += c->window;
  }
  return total;
}

// Add this new function to check if we have any established connections
int srtla_has_established_connections(void) {
  for (conn_t *c = conns; c != NULL; c = c->next) {
    if (!c->removed && c->last_rcvd > 0) {
      return 1;
    }
  }
  return 0;
}

// Update bitrate calculations for a specific connection when bytes are sent
static void update_connection_bitrate(conn_t *c, uint64_t bytes_sent) {
  // Initialize if this is the first time
  if (c->last_rate_update == 0) {
    c->last_rate_update = time(NULL);
    c->bytes_sent_window = 0;  // This will store last snapshot for difference calculation
    c->bytes_sent_total = 0;
  }
  
  // Always add bytes to total
  c->bytes_sent_total += bytes_sent;
}

// Update individual connection bitrate (matching Java's updateUploadSpeed method)
static void update_individual_connection_bitrate(conn_t *c) {
  if (!c || c->removed) return;
  
  time_t now = time(NULL);
  time_t time_diff = now - c->last_rate_update;
  
  // Update every 2 seconds like Java implementation
  if (time_diff >= 2) {
    uint64_t bytes_diff = c->bytes_sent_total - c->bytes_sent_window;
    
    if (time_diff > 0) {
      // Exact same calculation as Java: (bytesDiff * 8 * 1000.0) / timeDiff
      // Note: Using seconds instead of milliseconds, so no need for *1000
      c->current_bitrate_bps = (bytes_diff * 8.0) / time_diff;
      
      printf("SRTLA: Connection fd=%d speed update: %llu bytes in %ld sec = %.1f bps\n", 
             c->fd, (unsigned long long)bytes_diff, (long)time_diff, c->current_bitrate_bps);
    }
    
    c->last_rate_update = now;
    c->bytes_sent_window = c->bytes_sent_total; // Store current total as snapshot
  }
}

// Calculate total bitrate across all connections (matching Java approach)
static double calculate_total_bitrate(void) {
  double total_bitrate = 0.0;
  
  // First update all connection bitrates
  for (conn_t *c = conns; c != NULL; c = c->next) {
    if (!c->removed) {
      update_individual_connection_bitrate(c);
    }
  }
  
  // Sum bitrates from active connections (matching Java totalBitrate += conn.getUploadSpeed())
  for (conn_t *c = conns; c != NULL; c = c->next) {
    if (!c->removed) {
      total_bitrate += c->current_bitrate_bps;
      printf("SRTLA: Connection fd=%d contributing %.1f bps to total\n", 
             c->fd, c->current_bitrate_bps);
    }
  }
  
  // Convert to Mbps for display
  double mbps = total_bitrate / (1000.0 * 1000.0);
  
  printf("SRTLA: Total bitrate calculated: %.1f bps (%.2f Mbps)\n", total_bitrate, mbps);
  
  return mbps;
}

// Calculate load percentage for a specific connection
static int calculate_connection_load_percentage(conn_t *c) {
  if (c->removed || c->current_bitrate_bps == 0) return 0;
  
  // Calculate total bitrate across all active connections
  double total_bitrate = 0.0;
  for (conn_t *other = conns; other != NULL; other = other->next) {
    if (other->removed) continue;
    total_bitrate += other->current_bitrate_bps;
  }
  
  if (total_bitrate == 0) return 0;
  
  // Return percentage based on bitrate ratio
  return (int)((c->current_bitrate_bps * 100.0) / total_bitrate);
}

// Get detailed per-connection stats formatted as a string
// Format: "Total Bitrate: X.X Mbps\nIP:port|fd|active|inflight|window|age\n" for each connection
int srtla_get_connection_details(char* buffer, int buffer_size) {
  if (!buffer || buffer_size < 100) {
    return -1;
  }
  
  time_t now = time(NULL);
  int pos = 0;
  int conn_num = 0;
  
  // Add total bitrate header
  double total_bitrate = calculate_total_bitrate();
  pos += snprintf(buffer + pos, buffer_size - pos, "Total bitrate: %.1f Mbps", total_bitrate);
  
  for (conn_t *c = conns; c != NULL; c = c->next) {
    if (c->removed) continue;
    
    conn_num++;
    
    // Get connection addresses as strings
    char real_addr_str[64] = "unknown";
    char virtual_addr_str[64] = "none";
    
    if (c->src.sa_family == AF_INET) {
      struct sockaddr_in* sin = (struct sockaddr_in*)&c->src;
      snprintf(real_addr_str, sizeof(real_addr_str), "%s:%d", 
               inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
    }
    
    if (c->virtual_ip[0] != '\0') {
      snprintf(virtual_addr_str, sizeof(virtual_addr_str), "%s", c->virtual_ip);
    }
    
    // For sender, a connection is active if:
    // 1. It has a valid file descriptor, OR
    // 2. It has in-flight packets, OR  
    // 3. It was recently used for sending
    int is_active = (c->fd >= 0) || (c->in_flight_pkts > 0) || 
                    (c->last_sent > 0 && (now - c->last_sent) < CONN_TIMEOUT);
    
    // Determine connection type based on virtual IP or real IP
    const char* conn_type = "UNKNOWN";
    if (c->virtual_ip[0] != '\0') {
      // Use virtual IP to determine type
      if (strcmp(c->virtual_ip, "10.0.1.1") == 0) {
        conn_type = "WIFI";
      } else if (strcmp(c->virtual_ip, "10.0.2.1") == 0) {
        conn_type = "CELLULAR";
      } else if (strcmp(c->virtual_ip, "10.0.3.1") == 0) {
        conn_type = "ETHERNET";
      }
    } else {
      // Fallback: try to guess from real IP patterns
      if (c->src.sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)&c->src;
        uint32_t ip = ntohl(sin->sin_addr.s_addr);
        
        // Common patterns for connection types
        if ((ip & 0xFF000000U) == 0x64000000U ||     // 100.x.x.x (carrier-grade NAT)
            (ip & 0xFF000000U) == 0x0B000000U) {     // 11.x.x.x (some carriers)
          conn_type = "CELLULAR";
        } else if ((ip & 0xFFFF0000U) == 0xC0A80000U ||  // 192.168.x.x
                   (ip & 0xFFF00000U) == 0xAC100000U) {  // 172.16-31.x.x
          // Common private WiFi ranges
          conn_type = "WIFI";
        } else if ((ip & 0xFF000000U) == 0x0A000000U &&  // 10.x.x.x range
                   (ip & 0xFFFFFF00U) != 0x0A000100U &&  // Not 10.0.1.x (WiFi virtual)
                   (ip & 0xFFFFFF00U) != 0x0A000200U &&  // Not 10.0.2.x (Cellular virtual)
                   (ip & 0xFFFFFF00U) != 0x0A000300U) {  // Not 10.0.3.x (Ethernet virtual)
          // 10.x.x.x but not our virtual IP ranges - likely WiFi
          conn_type = "WIFI";
        } else if ((ip & 0xFF000000U) != 0x7F000000U &&  // Not 127.x.x.x (localhost)
                   (ip & 0xF0000000U) != 0xE0000000U &&  // Not 224-255.x.x.x (multicast/reserved)
                   ip != 0x00000000U) {                  // Not 0.0.0.0
          // Public IP - likely Ethernet/wired connection
          conn_type = "ETHERNET";
        }
        // Anything else stays as "UNKNOWN" (localhost, multicast, invalid IPs, etc.)
      }
    }
    
    // Calculate load percentage for this connection
    int load_percentage = calculate_connection_load_percentage(c);
    
    // Convert connection bitrate to Mbps for display
    double conn_bitrate_mbps = c->current_bitrate_bps / (1000.0 * 1000.0);
    
    // Add connection details to buffer with connection type, load info, and individual bitrate
    int written = snprintf(buffer + pos, buffer_size - pos,
                          "\n\n%s\n"
                          "  Bitrate: %.2f Mbps %d%%\n"
                          "  Window: %d\n"
                          "  Packets in-flight: %d",
                          conn_type,
                          conn_bitrate_mbps, load_percentage, c->window, c->in_flight_pkts);
    
    if (written < 0 || pos + written >= buffer_size - 1) {
      break; // Buffer full
    }
    pos += written;
  }
  
  return pos; // Return total bytes written
}

// Get individual connection bitrates for Android UI
// Returns number of connections, fills arrays with connection info
// Arrays must be pre-allocated with at least max_connections elements
int srtla_get_connection_bitrates(double* bitrates_mbps, char connection_types[][16], 
                                  char connection_ips[][64], int* load_percentages,
                                  int max_connections) {
  if (!bitrates_mbps || !connection_types || !connection_ips || !load_percentages) {
    return -1;
  }
  
  int conn_count = 0;
  time_t now = time(NULL);
  
  // Update all connection bitrates first
  for (conn_t *c = conns; c != NULL && conn_count < max_connections; c = c->next) {
    if (c->removed) continue;
    
    update_individual_connection_bitrate(c);
    
    // Convert bitrate to Mbps
    bitrates_mbps[conn_count] = c->current_bitrate_bps / (1000.0 * 1000.0);
    
    // Get connection type
    const char* conn_type = "UNKNOWN";
    if (c->virtual_ip[0] != '\0') {
      if (strcmp(c->virtual_ip, "10.0.1.1") == 0) {
        conn_type = "WIFI";
      } else if (strcmp(c->virtual_ip, "10.0.2.1") == 0) {
        conn_type = "CELLULAR";
      } else if (strcmp(c->virtual_ip, "10.0.3.1") == 0) {
        conn_type = "ETHERNET";
      }
    }
    strncpy(connection_types[conn_count], conn_type, 15);
    connection_types[conn_count][15] = '\0';
    
    // Get connection IP
    char addr_str[64] = "unknown";
    if (c->src.sa_family == AF_INET) {
      struct sockaddr_in* sin = (struct sockaddr_in*)&c->src;
      snprintf(addr_str, sizeof(addr_str), "%s:%d", 
               inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
    }
    strncpy(connection_ips[conn_count], addr_str, 63);
    connection_ips[conn_count][63] = '\0';
    
    // Get load percentage
    load_percentages[conn_count] = calculate_connection_load_percentage(c);
    
    conn_count++;
  }
  
  return conn_count;
}

// Get comprehensive connection data for UI visualization
// Returns number of connections, fills arrays with all connection info needed for ConnectionWindowData
int srtla_get_connection_window_data(double* bitrates_mbps, char connection_types[][16], 
                                    char connection_ips[][64], int* load_percentages,
                                    int* window_sizes, int* inflight_packets,
                                    int max_connections) {
  if (!bitrates_mbps || !connection_types || !connection_ips || !load_percentages || 
      !window_sizes || !inflight_packets) {
    return -1;
  }
  
  int conn_count = 0;
  time_t now = time(NULL);
  
  // Update all connection bitrates first
  for (conn_t *c = conns; c != NULL && conn_count < max_connections; c = c->next) {
    if (c->removed) continue;
    
    update_individual_connection_bitrate(c);
    
    // Convert bitrate to Mbps
    bitrates_mbps[conn_count] = c->current_bitrate_bps / (1000.0 * 1000.0);
    
    // Get actual window size and in-flight packets from native data
    window_sizes[conn_count] = c->window;
    inflight_packets[conn_count] = c->in_flight_pkts;
    
    // Get connection type
    const char* conn_type = "UNKNOWN";
    if (c->virtual_ip[0] != '\0') {
      if (strcmp(c->virtual_ip, "10.0.1.1") == 0) {
        conn_type = "WIFI";
      } else if (strcmp(c->virtual_ip, "10.0.2.1") == 0) {
        conn_type = "CELLULAR";
      } else if (strcmp(c->virtual_ip, "10.0.3.1") == 0) {
        conn_type = "ETHERNET";
      }
    }
    strncpy(connection_types[conn_count], conn_type, 15);
    connection_types[conn_count][15] = '\0';
    
    // Get connection IP
    char addr_str[64] = "unknown";
    if (c->src.sa_family == AF_INET) {
      struct sockaddr_in* sin = (struct sockaddr_in*)&c->src;
      snprintf(addr_str, sizeof(addr_str), "%s:%d", 
               inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
    }
    strncpy(connection_ips[conn_count], addr_str, 63);
    connection_ips[conn_count][63] = '\0';
    
    // Get load percentage
    load_percentages[conn_count] = calculate_connection_load_percentage(c);
    
    conn_count++;
  }
  
  return conn_count;
}

#endif // ANDROID
