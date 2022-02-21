#include <getopt.h>

#include <dc_application/command_line.h>
#include <dc_application/config.h>
#include <dc_application/options.h>
#include <dc_fsm/fsm.h>
#include <dc_posix/dc_stdlib.h>
#include <dc_posix/dc_stdio.h>
#include <dc_posix/dc_string.h>
#include <dc_posix/dc_signal.h>
#include <dc_posix/sys/dc_socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <dc_posix/dc_netdb.h>
#include <dc_posix/dc_unistd.h>
#include <dc_posix/dc_time.h>

#include "common.h"


struct application_settings
{
    struct dc_opt_settings opts;
    struct dc_setting_string *time;
    struct dc_setting_uint16 *num_packets;
    struct dc_setting_string *server_ip;
    struct dc_setting_uint16 *server_port;
    struct dc_setting_uint16 *size_packet;
    struct dc_setting_uint16 *delay;
};

struct client
{
    struct application_settings *app_settings;
    struct addrinfo tcp_hints;
    struct addrinfo *tcp_result;
    struct addrinfo udp_hints;
    struct addrinfo *udp_result;
    struct sockaddr *server_addr;
    int tcp_socket_fd;
    int udp_socket_fd;
};

enum application_states
{
    START_THREADS = DC_FSM_USER_START,  // 2
    OPEN_TCP_CONNECTION,                // 3
    OPEN_UDP_CONNECTION,                // 4
    SEND_INITIAL_MESSAGE,               // 5
    WAIT_FOR_START,                     // 6
    DO_TRAN,                            // 7
    SEND_CLOSING_MESSAGE,               // 8
    EXIT                                // 9
};

/**
 * @brief Atomic exit signal
 *
 */
static volatile sig_atomic_t exit_signal = 0;

static struct dc_application_settings *create_settings(const struct dc_posix_env *env, struct dc_error *err);
static int destroy_settings(const struct dc_posix_env *env,
                            struct dc_error *err,
                            struct dc_application_settings **psettings);
static int run(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings *settings);
static void error_reporter(const struct dc_error *err);
static void trace_reporter(const struct dc_posix_env *env,
                           const char *file_name,
                           const char *function_name,
                           size_t line_number);
static void signal_handler(int signnum);
static void will_change_state(const struct dc_posix_env *env,
                              struct dc_error *err,
                              const struct dc_fsm_info *info,
                              int from_state_id,
                              int to_state_id);
static void did_change_state(const struct dc_posix_env *env,
                             struct dc_error *err,
                             const struct dc_fsm_info *info,
                             int from_state_id,
                             int to_state_id,
                             int next_id);
static void bad_change_state(const struct dc_posix_env *env,
                             struct dc_error *err,
                             const struct dc_fsm_info *info,
                             int from_state_id,
                             int to_state_id);
static int start_threads(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int open_tcp_connection(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int open_udp_connection(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int send_initial_message(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int wait_for_start(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int do_tran(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int send_closing_message(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int do_exit(const struct dc_posix_env *env, struct dc_error *err, void *arg);
static int setup_udp(const struct dc_posix_env *env, struct dc_error *err, void *arg);


int main(int argc, char *argv[])
{
    dc_error_reporter reporter;
    dc_posix_tracer tracer;
    struct dc_posix_env env;
    struct dc_error err;
    struct dc_application_info *info;
    int ret_val;
    struct sigaction sa;

    reporter = error_reporter;
    tracer = trace_reporter;
    tracer = NULL;
    dc_error_init(&err, reporter);
    dc_posix_env_init(&env, tracer);
    dc_memset(&env, &sa, 0, sizeof(sa));
    sa.sa_handler = &signal_handler;
    dc_sigaction(&env, &err, SIGINT, &sa, NULL);
    dc_sigaction(&env, &err, SIGTERM, &sa, NULL);

    info = dc_application_info_create(&env, &err, "UDP Tester Client Application");
    ret_val = dc_application_run(&env, &err, info, create_settings, destroy_settings, run, dc_default_create_lifecycle, dc_default_destroy_lifecycle, "~./udp_tester_client.conf", argc, argv);
    dc_application_info_destroy(&env, &info);
    dc_error_reset(&err);

    return ret_val;
}

static struct dc_application_settings *create_settings(const struct dc_posix_env *env, struct dc_error *err)
{
    struct application_settings *settings;
    static const uint16_t default_packet_num = 100;
    static const uint16_t default_server_port = DEFAULT_UDP_TESTER_PORT;
    static const uint16_t default_packet_size = 100;
    static const uint16_t default_delay = 50;

    DC_TRACE(env);
    settings = dc_malloc(env, err, sizeof(struct application_settings));

    if(settings == NULL)
    {
        return NULL;
    }

    settings->opts.parent.config_path = dc_setting_path_create(env, err);
    settings->time = dc_setting_string_create(env, err);
    settings->num_packets = dc_setting_uint16_create(env, err);
    settings->server_ip = dc_setting_string_create(env, err);
    settings->server_port = dc_setting_uint16_create(env, err);
    settings->size_packet = dc_setting_uint16_create(env, err);
    settings->delay = dc_setting_uint16_create(env, err);

    struct options opts[] = {
            {(struct dc_setting *)settings->opts.parent.config_path,
                    dc_options_set_path,
                    "config",
                    required_argument,
                    'c',
                    "CONFIG",
                    dc_string_from_string,
                    NULL,
                    dc_string_from_config,
                    NULL},
            {(struct dc_setting *)settings->time,
                    dc_options_set_string,
                    "time",
                    required_argument,
                    't',
                    "TIME",
                    dc_string_from_string,
                    "time",
                    dc_string_from_config,
                    NULL},
            {(struct dc_setting *)settings->num_packets,
                    dc_options_set_uint16,
                    "num_packets",
                    required_argument,
                    'n',
                    "NUM_PACKETS",
                    dc_uint16_from_string,
                    "num_packets",
                    dc_uint16_from_config,
                    &default_packet_num},
            {(struct dc_setting *)settings->server_ip,
                    dc_options_set_string,
                    "ip",
                    required_argument,
                    'i',
                    "IP",
                    dc_string_from_string,
                    "ip",
                    dc_string_from_config,
                    NULL},
            {(struct dc_setting *)settings->server_port,
                    dc_options_set_uint16,
                    "port",
                    required_argument,
                    'p',
                    "PORT",
                    dc_uint16_from_string,
                    "port",
                    dc_uint16_from_config,
                    &default_server_port},
            {(struct dc_setting *)settings->size_packet,
                    dc_options_set_uint16,
                    "size_packets",
                    required_argument,
                    's',
                    "SIZE_PACKETS",
                    dc_uint16_from_string,
                    "size_packets",
                    dc_uint16_from_config,
                    &default_packet_size},
            {(struct dc_setting *)settings->delay,
                    dc_options_set_uint16,
                    "delay",
                    required_argument,
                    'd',
                    "DELAY",
                    dc_uint16_from_string,
                    "delay",
                    dc_uint16_from_config,
                    &default_delay},
    };

    // note the trick here - we use calloc and add 1 to ensure the last line is all 0/NULL
    settings->opts.opts_count = (sizeof(opts) / sizeof(struct options)) + 1;
    settings->opts.opts_size = sizeof(struct options);
    settings->opts.opts = dc_calloc(env, err, settings->opts.opts_count, settings->opts.opts_size);
    dc_memcpy(env, settings->opts.opts, opts, sizeof(opts));
    settings->opts.flags = "m:";
    settings->opts.env_prefix = "DC_EXAMPLE_";

    return (struct dc_application_settings *)settings;
}

static int destroy_settings(const struct dc_posix_env *env,
                            __attribute__((unused)) struct dc_error *err,
                            struct dc_application_settings **psettings)
{
    struct application_settings *app_settings;

    DC_TRACE(env);
    app_settings = (struct application_settings *)*psettings;

    dc_setting_string_destroy(env, &app_settings->time);
    dc_setting_uint16_destroy(env, &app_settings->num_packets);
    dc_setting_string_destroy(env, &app_settings->server_ip);
    dc_setting_uint16_destroy(env, &app_settings->server_port);
    dc_setting_uint16_destroy(env, &app_settings->size_packet);
    dc_setting_uint16_destroy(env, &app_settings->delay);

    dc_free(env, app_settings->opts.opts, app_settings->opts.opts_count);
    dc_free(env, *psettings, sizeof(struct application_settings));

    if(env->null_free)
    {
        *psettings = NULL;
    }

    return 0;
}

static int run(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings *settings)
{
    struct application_settings *app_settings;
    struct dc_fsm_info *fsm_info;
    int ret_val;
    struct client client;

    DC_TRACE(env);

    app_settings = (struct application_settings *)settings;
    client.app_settings = app_settings;

    static struct dc_fsm_transition transitions[] = {
            {DC_FSM_INIT, START_THREADS, start_threads},
            {START_THREADS, OPEN_TCP_CONNECTION, open_tcp_connection},
            {OPEN_TCP_CONNECTION, OPEN_UDP_CONNECTION, open_udp_connection},
            {OPEN_UDP_CONNECTION, SEND_INITIAL_MESSAGE, send_initial_message},
            {SEND_INITIAL_MESSAGE, WAIT_FOR_START, wait_for_start},
            {WAIT_FOR_START, DO_TRAN, do_tran},
            {DO_TRAN, SEND_CLOSING_MESSAGE, send_closing_message},
            {SEND_CLOSING_MESSAGE, EXIT, do_exit},
            {EXIT, DC_FSM_EXIT, NULL}
    };

    ret_val = EXIT_SUCCESS;
    fsm_info = dc_fsm_info_create(env, err, "udp_tester_client");
//    dc_fsm_info_set_will_change_state(fsm_info, will_change_state);
    dc_fsm_info_set_did_change_state(fsm_info, did_change_state);
    dc_fsm_info_set_bad_change_state(fsm_info, bad_change_state);

    if(dc_error_has_no_error(err))
    {
        int from_state;
        int to_state;

        ret_val = dc_fsm_run(env, err, fsm_info, &from_state, &to_state, &client, transitions);
        dc_fsm_info_destroy(env, &fsm_info);
    }

    return ret_val;
}

static int start_threads(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{
    int ret_val;
    ret_val = OPEN_TCP_CONNECTION;
    return ret_val;
}

static int open_tcp_connection(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{

    return OPEN_UDP_CONNECTION;

    struct client *client;
    int next_state;
    const char *hostname;

    client = (struct client *)arg;

    hostname = dc_setting_string_get(env, client->app_settings->server_ip);
    dc_memset(env, &(client->tcp_hints), 0, sizeof(client->tcp_hints));
    client->tcp_hints.ai_family   = AF_INET;    // PF_INET6;
    client->tcp_hints.ai_socktype = SOCK_STREAM;
    client->tcp_hints.ai_flags    = AI_CANONNAME;
    dc_getaddrinfo(env, err, hostname, NULL, &(client->tcp_hints), &(client->tcp_result));

    if(dc_error_has_no_error(err))
    {
        // create socket
        client->tcp_socket_fd =
                dc_socket(env, err, client->tcp_result->ai_family, client->tcp_result->ai_socktype, client->tcp_result->ai_protocol);

        if(dc_error_has_no_error(err))
        {
            struct sockaddr *sockaddr;
            in_port_t        port;
            in_port_t        converted_port;
            socklen_t        sockaddr_size;

            sockaddr       = client->tcp_result->ai_addr;

            port           = dc_setting_uint16_get(env, client->app_settings->server_port);
            converted_port = htons(port);


            if(sockaddr->sa_family == AF_INET)
            {
                struct sockaddr_in *addr_in;

                addr_in           = (struct sockaddr_in *)sockaddr;
                addr_in->sin_port = converted_port;
                sockaddr_size     = sizeof(struct sockaddr_in);
            }
            else
            {
                if(sockaddr->sa_family == AF_INET6)
                {
                    struct sockaddr_in6 *addr_in;

                    addr_in            = (struct sockaddr_in6 *)sockaddr;
                    addr_in->sin6_port = converted_port;
                    sockaddr_size      = sizeof(struct sockaddr_in6);
                }
                else
                {
                    DC_ERROR_RAISE_USER(err, "sockaddr->sa_family is invalid", -1);
                    sockaddr_size = 0;
                }
            }

            if(dc_error_has_no_error(err))
            {
                // bind tcp_address (port) to socket
                dc_connect(env, err, client->tcp_socket_fd, sockaddr, sockaddr_size);
                // go to next state
                next_state = SEND_INITIAL_MESSAGE;
                return next_state;
            }
        }
    }

    return OPEN_UDP_CONNECTION;
}

static int send_initial_message(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{
    return WAIT_FOR_START;

    struct client *client;
    const char *time;
    uint16_t num_packets;
    uint16_t size_packets;
    uint16_t delay;
    const size_t max = 5000;
    char buf[max];

    client = (struct client *) arg;

    time = dc_setting_string_get(env, client->app_settings->time);
    num_packets = dc_setting_uint16_get(env, client->app_settings->num_packets);
    size_packets = dc_setting_uint16_get(env, client->app_settings->size_packet);
    delay = dc_setting_uint16_get(env, client->app_settings->delay);

    // write message containing time, num packets, size of packets, and delay
    snprintf(buf, max - 1, "%s %u %u %u ", time, num_packets, size_packets, delay);

    dc_write(env, err, client->tcp_socket_fd, buf, dc_strlen(env, buf));

    return WAIT_FOR_START;
}

static int wait_for_start(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{
    struct client *client;

    client = (struct client *) arg;

    if (dc_setting_string_get(env, client->app_settings->time))
    {
        // wait till time
    }

    return DO_TRAN;
}

static int open_udp_connection(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{
    struct client *client;
    const char *hostname;

    client = (struct client *) arg;

    hostname = dc_setting_string_get(env, client->app_settings->server_ip);

    if (dc_error_has_no_error(err))
    {
        client->udp_socket_fd = dc_socket(
                env, err, AF_INET, SOCK_DGRAM, 0);

        if(dc_error_has_no_error(err))
        {
            struct sockaddr_in *sockaddr;
            uint16_t port = dc_setting_uint16_get(env, client->app_settings->server_port);

            sockaddr = dc_calloc(env, err, 1, sizeof(struct sockaddr));
            sockaddr->sin_family = AF_INET;
            sockaddr->sin_port = htons(port);
            sockaddr->sin_addr.s_addr = inet_addr(hostname);

            client->server_addr = (struct sockaddr *)sockaddr;
        }
    }

    return SEND_INITIAL_MESSAGE;
}

static int do_tran(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{
    struct client *client;
    size_t i;
    size_t num_packets;
    size_t size_packet;
    size_t delay_milliseconds;
    struct timespec delay;


    client = (struct client *) arg;

    num_packets = dc_setting_uint16_get(env, client->app_settings->num_packets);
    size_packet = dc_setting_uint16_get(env, client->app_settings->size_packet);
    delay_milliseconds = dc_setting_uint16_get(env, client->app_settings->delay);
    delay.tv_nsec = (long)delay_milliseconds * 1000;
    delay.tv_sec = 0;

    char msg[size_packet];

    // write messages on delay
    // message format: messageIDnum

    for (i = 1; i <= num_packets; ++i)
    {
        sprintf(msg, "%zu %zu ", i, num_packets);
        dc_sendto(env, err, client->udp_socket_fd, msg, size_packet, 0, client->server_addr, sizeof(*client->server_addr));
        dc_nanosleep(env, err, &delay, NULL);
    }

    return SEND_CLOSING_MESSAGE;
}

static int send_closing_message(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{
    /**
    struct client *client;

    client = (struct client *) arg;

    dc_write(env, err, client->tcp_socket_fd, "fin", 3);
     **/
    return EXIT;
}

static int do_exit(const struct dc_posix_env *env, struct dc_error *err, void *arg)
{
    struct client *client;

    client = (struct client *) arg;

//    dc_close(env, err, client->tcp_socket_fd);
    dc_close(env, err, client->udp_socket_fd);

    // TODO: free allocated memory
//    dc_freeaddrinfo(env, client->tcp_result);

    return DC_FSM_EXIT;
}

static void will_change_state(const struct dc_posix_env *env,
                              struct dc_error *err,
                              const struct dc_fsm_info *info,
                              int from_state_id,
                              int to_state_id)
{
    printf("%s: will change %d -> %d\n", dc_fsm_info_get_name(info), from_state_id, to_state_id);
}

static void did_change_state(const struct dc_posix_env *env,
                             struct dc_error *err,
                             const struct dc_fsm_info *info,
                             int from_state_id,
                             int to_state_id,
                             int next_id)
{
    printf("%s: did change %d -> %d moving to %d\n", dc_fsm_info_get_name(info), from_state_id, to_state_id, next_id);
}

static void bad_change_state(const struct dc_posix_env *env,
                             struct dc_error *err,
                             const struct dc_fsm_info *info,
                             int from_state_id,
                             int to_state_id)
{
    printf("%s: bad change %d -> %d\n", dc_fsm_info_get_name(info), from_state_id, to_state_id);
}

void signal_handler(__attribute__((unused)) int signnum)
{
    printf("\nSIGNAL CAUGHT!\n");
    exit_signal = 1;
}

static void error_reporter(const struct dc_error *err)
{
    fprintf(stderr, "ERROR: %s : %s : @ %zu : %d\n", err->file_name, err->function_name, err->line_number, 0);
    fprintf(stderr, "ERROR: %s\n", err->message);
}

static void trace_reporter(__attribute__((unused)) const struct dc_posix_env *env,
                           const char *file_name,
                           const char *function_name,
                           size_t line_number)
{
    fprintf(stdout, "TRACE: %s : %s : @ %zu\n", file_name, function_name, line_number);
}
