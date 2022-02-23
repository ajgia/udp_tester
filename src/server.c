#include <dc_application/command_line.h>
#include <dc_application/config.h>
#include <dc_application/defaults.h>
#include <dc_application/environment.h>
#include <dc_application/options.h>
#include <dc_network/server.h>
#include <dc_network/common.h>
#include <dc_network/options.h>
#include <dc_network/common.h>
#include <dc_network/options.h>
#include <dc_network/server.h>
#include <dc_fsm/fsm.h>
#include <dc_posix/dc_fcntl.h>
#include <dc_posix/dc_netdb.h>
#include <dc_posix/dc_posix_env.h>
#include <dc_posix/dc_signal.h>
#include <dc_posix/dc_stdlib.h>
#include <dc_posix/dc_string.h>
#include <dc_posix/dc_time.h>
#include <dc_posix/dc_unistd.h>
#include <dc_posix/sys/dc_socket.h>
#include <dc_posix/dc_stdio.h>
#include <dc_posix/dc_inttypes.h>
#include <dc_util/dump.h>
#include <dc_util/streams.h>
#include <dc_util/types.h>

#include <getopt.h>
#include <arpa/inet.h>

#include "common.h"

struct application_settings
{
    struct dc_opt_settings opts;
    struct dc_setting_uint16 *port;
    struct dc_setting_string *server_ip;
    struct addrinfo *tcp_address;
    struct addrinfo *udp_address;
    int tcp_server_socket_fd;
    int udp_server_socket_fd;
    struct sockaddr_in server_addr, client_addr;
};


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
static void destroy_server_lifecycle(const struct dc_posix_env *env,
                                     struct dc_server_lifecycle **plifecycle);
static struct dc_server_lifecycle *create_server_lifecycle(
        const struct dc_posix_env *env, struct dc_error *err);
static void do_create_settings(const struct dc_posix_env *env,
                               struct dc_error *err, void *arg);
static void do_create_socket(const struct dc_posix_env *env,
                             struct dc_error *err, void *arg);
static void do_set_sockopts(const struct dc_posix_env *env,
                            struct dc_error *err, void *arg);
static void do_bind(const struct dc_posix_env *env, struct dc_error *err,
                    void *arg);
static void do_listen(const struct dc_posix_env *env, struct dc_error *err,
                      void *arg);
static void do_setup(const struct dc_posix_env *env, struct dc_error *err,
                     void *arg);
static bool do_accept(const struct dc_posix_env *env, struct dc_error *err,
                      int *client_socket_fd, void *arg);
static void do_shutdown(const struct dc_posix_env *env, struct dc_error *err,
                        void *arg);
static void do_destroy_settings(const struct dc_posix_env *env,
                                struct dc_error *err, void *arg);
void signal_handler(int signnum);
void echo(const struct dc_posix_env *env, struct dc_error *err, int client_socket_fd);


/**
 * @brief Atomic exit signal
 *
 */
static volatile sig_atomic_t exit_signal = 0;

int main(int argc, char *argv[])
{
    dc_posix_tracer tracer;
    dc_error_reporter reporter;
    struct dc_posix_env env;
    struct dc_error err;
    struct dc_application_info *info;
    int ret_val;
    struct sigaction sa;

    tracer = dc_posix_default_tracer;
    tracer = NULL;
    dc_posix_env_init(&env, tracer);
    reporter = dc_error_default_error_reporter;
    dc_error_init(&err, reporter);
    dc_memset(&env, &sa, 0, sizeof(sa));
    sa.sa_handler = &signal_handler;
    sa.sa_flags = 0;
    dc_sigaction(&env, &err, SIGINT, &sa, NULL);
    dc_sigaction(&env, &err, SIGTERM, &sa, NULL);

    info = dc_application_info_create(&env, &err, "UDP Tester Server");
    ret_val = dc_application_run(&env, &err, info, create_settings, destroy_settings, run, dc_default_create_lifecycle, dc_default_destroy_lifecycle, "~./udp_tester_server.conf", argc, argv);
    dc_application_info_destroy(&env, &info);
    dc_error_reset(&err);

    return ret_val;
}

static struct dc_application_settings *create_settings(const struct dc_posix_env *env, struct dc_error *err)
{
    struct application_settings *settings;

    static const uint16_t default_port = DEFAULT_UDP_TESTER_PORT;
    static const char *default_hostname = "127.0.0.1";

    DC_TRACE(env);
    settings = dc_malloc(env, err, sizeof(struct application_settings));

    if(settings == NULL)
    {
        return NULL;
    }

    settings->opts.parent.config_path = dc_setting_path_create(env, err);
    settings->port = dc_setting_uint16_create(env, err);
    settings->server_ip = dc_setting_string_create(env, err);

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
            {(struct dc_setting *)settings->port,
                    dc_options_set_uint16,
                    "port",
                    required_argument,
                    'p',
                    "PORT",
                    dc_uint16_from_string,
                    "port",
                    dc_uint16_from_config,
                    &default_port},
            {(struct dc_setting *)settings->server_ip,
                    dc_options_set_string,
                    "ip",
                    required_argument,
                    'i',
                    "IP",
                    dc_string_from_string,
                    "ip",
                    dc_string_from_config,
                    default_hostname},
    };

    // note the trick here - we use calloc and add 1 to ensure the last line is all 0/NULL
    settings->opts.opts_count = (sizeof(opts) / sizeof(struct options)) + 1;
    settings->opts.opts_size = sizeof(struct options);
    settings->opts.opts = dc_calloc(env, err, settings->opts.opts_count, settings->opts.opts_size);
    dc_memcpy(env, settings->opts.opts, opts, sizeof(opts));
    settings->opts.flags = "m:";
    settings->opts.env_prefix = "UDP_TESTER_";

    return (struct dc_application_settings *)settings;
}

static int destroy_settings(const struct dc_posix_env *env,
                            __attribute__((unused)) struct dc_error *err,
                            struct dc_application_settings **psettings)
{
    struct application_settings *app_settings;

    DC_TRACE(env);
    app_settings = (struct application_settings *)*psettings;
    dc_setting_uint16_destroy(env, &app_settings->port);
    dc_setting_string_destroy(env, &app_settings->server_ip);
    dc_free(env, app_settings->opts.opts, app_settings->opts.opts_size);
    dc_free(env, *psettings, sizeof(struct application_settings));

    if(env->null_free)
    {
        *psettings = NULL;
    }

    return 0;
}

static struct dc_server_lifecycle *create_server_lifecycle(
        const struct dc_posix_env *env, struct dc_error *err)
{
    struct dc_server_lifecycle *lifecycle;

    lifecycle = dc_server_lifecycle_create(env, err);
    dc_server_lifecycle_set_create_settings(env, lifecycle, do_create_settings);
    dc_server_lifecycle_set_create_socket(env, lifecycle, do_create_socket);
    dc_server_lifecycle_set_set_sockopts(env, lifecycle, do_set_sockopts);
    dc_server_lifecycle_set_bind(env, lifecycle, do_bind);
    dc_server_lifecycle_set_listen(env, lifecycle, do_listen);
    dc_server_lifecycle_set_setup(env, lifecycle, do_setup);
    dc_server_lifecycle_set_accept(env, lifecycle, do_accept);
    dc_server_lifecycle_set_shutdown(env, lifecycle, do_shutdown);
    dc_server_lifecycle_set_destroy_settings(env, lifecycle,
                                             do_destroy_settings);

    return lifecycle;
}

static void destroy_server_lifecycle(const struct dc_posix_env *env,
                                     struct dc_server_lifecycle **plifecycle)
{
    DC_TRACE(env);
    dc_server_lifecycle_destroy(env, plifecycle);
}

static int run(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings *settings)
{
    int ret_val;
    struct dc_server_info *info;

    DC_TRACE(env);

    info = dc_server_info_create(env, err, "udp_tester_server", NULL, settings);

    if (dc_error_has_no_error(err))
    {
        dc_server_run(env, err, info, create_server_lifecycle, destroy_server_lifecycle);
        dc_server_info_destroy(env, &info);
    }

    if (dc_error_has_no_error(err))
    {
        ret_val = 0;
    }
    else
    {
        ret_val = -1;
    }

    return ret_val;
}

void signal_handler(__attribute__ ((unused)) int signnum)
{
    printf("caught %d\n", signnum);
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

static void do_create_settings(const struct dc_posix_env *env,
                               struct dc_error *err, void *arg)
{
    struct application_settings *app_settings;
    int family;
    const char *hostname;

    DC_TRACE(env);
    app_settings = arg;

    family = AF_INET;
    hostname = dc_setting_string_get(env, app_settings->server_ip);

    dc_network_get_addresses(env, err, family, SOCK_STREAM, hostname,
                             &app_settings->tcp_address);
    dc_network_get_addresses(env, err, family, SOCK_DGRAM, hostname,
                             &app_settings->udp_address);
}

static void do_create_socket(const struct dc_posix_env *env,
                             struct dc_error *err, void *arg)
{
    struct application_settings *app_settings;

    int tcp_socket_fd;
    int udp_socket_fd;

    DC_TRACE(env);
    app_settings = arg;

    tcp_socket_fd = dc_network_create_socket(env, err, app_settings->tcp_address);
    if (dc_error_has_no_error(err))
    {
        app_settings->tcp_server_socket_fd = tcp_socket_fd;
    }
    else
    {

        app_settings->tcp_server_socket_fd = -1;
    }
    printf("tcp socket: %d\n", app_settings->tcp_server_socket_fd);

    udp_socket_fd = dc_network_create_socket(env, err, app_settings->udp_address);
    if (dc_error_has_no_error(err))
    {
        app_settings->udp_server_socket_fd = udp_socket_fd;
    }
    else
    {
        app_settings->udp_server_socket_fd = -1;
    }

}

static void do_set_sockopts(const struct dc_posix_env *env,
                            struct dc_error *err, void *arg)
{
    struct application_settings *app_settings;
    bool reuse_address;

    DC_TRACE(env);
    app_settings = arg;
    reuse_address = false;

    dc_network_opt_ip_so_reuse_addr(env, err, app_settings->tcp_server_socket_fd,
                                    reuse_address);
    dc_network_opt_ip_so_reuse_addr(env, err, app_settings->udp_server_socket_fd,
                                    reuse_address);

    // set timeout for udp
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    if (dc_setsockopt(env, err, app_settings->udp_server_socket_fd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0)
    {
        perror("Error setting timeout\n");
    }
}

static void do_bind(const struct dc_posix_env *env, struct dc_error *err,
                    void *arg)
{
    struct application_settings *app_settings;
    uint16_t port;

    DC_TRACE(env);
    app_settings = arg;
    port = dc_setting_uint16_get(env, app_settings->port);

    dc_network_bind(env, err, app_settings->tcp_server_socket_fd,
                    app_settings->tcp_address->ai_addr, port);

    if (dc_error_has_error(err))
    {
        printf("TCP couldn't bind to the port\n");
    }

    dc_network_bind(env, err, app_settings->udp_server_socket_fd,
                    app_settings->udp_address->ai_addr, port + 1);
    if (dc_error_has_error(err))
    {
        printf("UDP Couldn't bind to the port\n");
    }

}

static void do_listen(const struct dc_posix_env *env, struct dc_error *err,
                      void *arg)
{
    struct application_settings *app_settings;
    int backlog;

    DC_TRACE(env);
    app_settings = arg;
    backlog = 5;
    dc_network_listen(env, err, app_settings->tcp_server_socket_fd, backlog);
}

static void do_setup(const struct dc_posix_env *env,
                     __attribute__((unused)) struct dc_error *err,
                     __attribute__((unused)) void *arg)
{
    DC_TRACE(env);
}

static bool do_accept(const struct dc_posix_env *env, struct dc_error *err,
                      int *client_socket_fd, void *arg)
{
    struct application_settings *app_settings;
    bool ret_val;
    size_t buf_size = 500;
    char message[buf_size];

    DC_TRACE(env);
    app_settings = arg;
    ret_val = false;

    printf("accepting\n");
    *client_socket_fd = dc_network_accept(env, err, app_settings->tcp_server_socket_fd);
    printf("accepted\n");

    if (dc_error_has_error(err))
    {
        if (exit_signal == true && dc_error_is_errno(err, EINTR))
        {
            ret_val = true;
            dc_error_reset(err);
        }
    }
    else
    {

        struct sockaddr client_addr;
        socklen_t client_addr_len;
        ssize_t nread;
        int out_fd;
        char s[100];

        out_fd = dc_open(env, err, "./log.csv", DC_O_WRONLY | DC_O_TRUNC | DC_O_CREAT, 0777);
        if (dc_error_has_error(err))
        {
            fprintf(stderr, "%s\n", err->message);
        }

        while ((dc_recvfrom(env, err, app_settings->udp_server_socket_fd,
                            message, buf_size, 0, &client_addr, &client_addr_len)
               ) > 0 && dc_error_has_no_error(err) )
        {
            struct sockaddr_in *addr_in = (struct sockaddr_in *) &client_addr;
            char address[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr_in->sin_addr, address, sizeof(address));
            uint16_t port = htons (addr_in->sin_port);
            sprintf(s, "%s,%s,%u\n", message, address, port);

            dc_write(env, err, out_fd, s, strlen(s));
            dc_write(env, err, fileno(stdout), s, strlen(s));
            dc_error_reset(err);
        }
    }
    dc_error_reset(err);
    printf("done. exiting. 'resource temporarily unavailable' error below is expected due to timeout\n");

    ret_val = true;
    return ret_val;
}

void echo(const struct dc_posix_env *env, struct dc_error *err, int client_socket_fd)
{
    struct dc_dump_info *dump_info;
    struct dc_stream_copy_info *copy_info;

    DC_TRACE(env);
    dump_info = dc_dump_info_create(env, err, STDOUT_FILENO, dc_max_off_t(env));

    if(dc_error_has_no_error(err))
    {
        copy_info = dc_stream_copy_info_create(env, err, NULL, dc_dump_dumper, dump_info, NULL, NULL);

        if(dc_error_has_no_error(err))
        {
            dc_stream_copy(env, err, client_socket_fd, client_socket_fd, 1024, copy_info);

            if(dc_error_has_no_error(err))
            {
                dc_stream_copy_info_destroy(env, &copy_info);
            }
        }

        dc_dump_info_destroy(env, &dump_info);
    }
}


static void do_shutdown(const struct dc_posix_env *env,
                        __attribute__((unused)) struct dc_error *err,
                        __attribute__((unused)) void *arg)
{
    DC_TRACE(env);
}

static void do_destroy_settings(const struct dc_posix_env *env,
                                __attribute__((unused)) struct dc_error *err,
                                void *arg)
{
    struct application_settings *app_settings;

    DC_TRACE(env);
    app_settings = arg;
    dc_freeaddrinfo(env, app_settings->tcp_address);
}
