#include <dc_application/command_line.h>
#include <dc_application/config.h>
#include <dc_application/options.h>
#include <dc_posix/dc_stdlib.h>
#include <dc_posix/dc_stdio.h>
#include <dc_posix/dc_string.h>
#include <dc_posix/dc_signal.h>

#include <getopt.h>

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
    static const uint16_t default_packet_num = 5;
    static const uint16_t default_server_port = DEFAULT_UDP_TESTER_PORT;
    static const uint16_t default_packet_size = 10;
    static const uint16_t default_delay = 200;

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

    DC_TRACE(env);

    app_settings = (struct application_settings *)settings;

    printf("client says hi\n");

    return EXIT_SUCCESS;
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
