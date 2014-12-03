
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>

#include <yajl/yajl_tree.h>


extern const char *__progname;

static const struct option cmd_options[] =
{
    {"foreground", 0, 0, 'f'},
    {"address", 1, 0, 'a'},
    {"port", 1, 0, 'p'},
    {"help", 0, 0, 'h'},
    {"fifo", 1, 0, 's'},
    {"pidfile", 1, 0, 'i'},
    {"debug", 0, 0, 'd'},
    {0, 0, 0, 0}
};

static const char *opt_spec = "fhda:p:s:i:";
static const char *def_pid_file = "/var/run/udp-gw.pid";
static int log_level = LOG_INFO;
static int log_to_stderr = 1;

struct udp_gw_opts
{
    int foreground;
    char *pid_file;
    struct sockaddr_in udp_address;
    char *fifo_path;
    int fifofd;
    int sockfd;

    int has_help;
    int has_address;
    int has_port;
    int has_fifo;
};


static void
cleanup(struct udp_gw_opts *pgwopts)
{
    if( 0 != pgwopts->fifofd )
        close(pgwopts->fifofd);

    if( 0 != pgwopts->sockfd )
        close(pgwopts->sockfd);

    if( NULL != pgwopts->fifo_path )
        free(pgwopts->fifo_path);

    if( NULL != pgwopts->pid_file )
        free(pgwopts->pid_file);
}

static void
usage()
{
    fprintf(stderr, "Usage: %s <ARGS> [OPTION]...\n\n", __progname);
    fprintf(stderr, " Mandatorary ARGS:\n");
    fprintf(stderr, " -a, --address         Address to send UDP packets to\n");
    fprintf(stderr, " -p, --port            UDP port to send packets to\n");
    fprintf(stderr, " -s, --fifo            Path to control FIFO\n");
    fprintf(stderr, "\n Optional OPTIONS:\n");
    fprintf(stderr, " -f, --foreground      Do not daemonize\n");
    fprintf(stderr, " -i, --pidfile         Path to PID file\n");
    fprintf(stderr, " -d, --debug           Log extra debug info\n");
    fprintf(stderr, " -h, --help            Print this help message\n");
}

static int
process_cmdline(int argc, char *argv[], struct udp_gw_opts *pgwopts)
{
    int c;

    memset(pgwopts, 0, sizeof(*pgwopts));
    pgwopts->udp_address.sin_family = AF_INET;

    while(1)
    {
        int this_opt_ind = optind ? optind : 1;
        int option_index = 0;

        c = getopt_long(argc, argv, opt_spec, cmd_options, &option_index );
        if( c == -1 )
            break;

        switch(c)
        {
        case 'f':
            pgwopts->foreground = 1;
            break;
        case 'd':
            log_level = LOG_DEBUG;
            break;
        case 'a':
        {
            struct hostent *hp;
            if( (hp=gethostbyname(optarg)) == NULL )
            {
                pgwopts->udp_address.sin_addr.s_addr = inet_addr(optarg);
                if( pgwopts->udp_address.sin_addr.s_addr == -1 )
                {
                    fprintf(stderr, "Unknown host\n");
                    return 1;
                }
            }
            else
            {
                pgwopts->udp_address.sin_addr = *(struct in_addr *)(hp->h_addr_list[0]);
            }

            pgwopts->has_address = 1;
            break;
        }
        case 'p':
            pgwopts->udp_address.sin_port = htons(atoi(optarg));
            pgwopts->has_port = 1;
            break;
        case 's':
            pgwopts->fifo_path = strdup(optarg);
            if( NULL == pgwopts->fifo_path )
            {
                fprintf(stderr, "Out of memory");
                return 1;
            }

            pgwopts->has_fifo = 1;
            break;
        case 'i':
            pgwopts->pid_file = strdup(optarg);
            if( NULL == pgwopts->pid_file )
            {
                fprintf(stderr, "Out of memory");
                return 1;
            }

        case 'h':
            usage();
            pgwopts->has_help = 1;
            return 0;
        }
    }

    if( optind < argc )
    {
        usage();
        return 1;
    }

    // Defaults
    if( NULL == pgwopts->pid_file )
        pgwopts->pid_file = strdup(def_pid_file);

    return 0;
}


int
udpgwlog( int level, const char *format, ... )
{
    static int opened = 0;

    va_list vargs;
    va_start(vargs, format);

    if( log_to_stderr )
    {
        if( level > log_level )
            return 0;

        vfprintf(stderr, format, vargs);
        fputc('\n', stderr);
    }
    else
    {
        if( ! opened )
        {
            openlog(__progname, LOG_NDELAY|LOG_PID|LOG_CONS, LOG_DAEMON);
            opened = 1;
        }
        vsyslog(level, format, vargs);
    }

    return 0;
}


int
daemonise(void)
{
    int pid = fork();
    if( pid < 0 ) {
        udpgwlog(LOG_ERR, "Failed to fork: %s", strerror(errno));
        return 0;
    }
     
    // parent
    if( pid > 0 )
        exit(0);

    // Child..

    // detach term
    setsid();

    // Close FDs
    for(int i=getdtablesize(); i>=0; --i)
        close(i);

    // Open stdin/out/err
    int s = open("/dev/null", O_RDWR);      // stdin
    dup(s);     // stdout
    dup(s);     // stderr;

    chdir("/");
    log_to_stderr = 0;

    return 1; 
}

static
int open_fifo( struct udp_gw_opts *pgwopts )
{
    int res;

    struct stat sb;
    res = stat(pgwopts->fifo_path, &sb);
    if( 0 == res )
    {
        // Exists, make sure its a fifo..
        if( ! S_ISFIFO(sb.st_mode) )
        {
            udpgwlog(LOG_ERR, "Path [%s] exists but is not a fifo", pgwopts->fifo_path);
            return 1;
        }
    }
    else
    {
        // Doesn't exist, try to create it
        if( ENOENT == errno )
        {
            res = mkfifo(pgwopts->fifo_path, 0666 );
            if( 0 != res )
            {
                udpgwlog(LOG_ERR, "Failed to create fifo [%s] : %s", pgwopts->fifo_path, strerror(errno));
                return 1;
            }
        }
        else
        {
            udpgwlog(LOG_ERR, "Failed to stat fifo [%s] : %s", pgwopts->fifo_path, strerror(errno));
            return 1;
        }
    }

    // Linux specific : open for read and write to avoid blocking when there is no
    // writer attached.  This is not portable!
    pgwopts->fifofd =  open(pgwopts->fifo_path, O_RDWR);
    if( -1 == pgwopts->fifofd )
    {
        udpgwlog(LOG_ERR, "Failed to open fifo [%s] : %s", pgwopts->fifo_path, strerror(errno));
        return 1;
    }

    return 0;
}

static int
open_socket( struct udp_gw_opts *pgwopts )
{
    // Open the UDP socket
    pgwopts->sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    if( -1 == pgwopts->sockfd )
    {
        udpgwlog(LOG_ERR, "Failed to open socket: %s", strerror(errno));
        return 1;
    }

    // Enable broadcasts in case the supplied address is a broadcast
    int bEnabled = 1;
    setsockopt(pgwopts->sockfd, SOL_SOCKET, SO_BROADCAST, &bEnabled, sizeof(bEnabled) );

    // Connect the socket so we can use send()
    int res = connect(pgwopts->sockfd,
                      (const struct sockaddr *) &pgwopts->udp_address,
                      sizeof(struct sockaddr_in) );
    if( 0 != res )
    {
        udpgwlog(LOG_ERR, "Failed to connect socket: %s", strerror(errno));
        return 1;
    }


    return 0;
}


static const char *
json_get(yajl_val node, const char *key, int required)
{
    const char *path[] = { key, NULL };

    yajl_val v = yajl_tree_get(node, path, yajl_t_string);
    if( NULL == v  && required )
    {
        udpgwlog(LOG_ERR, "Required parameter '%s' missing from JSON input", key);
    }

    return (NULL == v) ? NULL : YAJL_GET_STRING(v);
}


static int
process_data( struct udp_gw_opts *pgwopts, void *data, size_t data_sz )
{
    yajl_val node;
    char buff[1024];
    int ret = 0;

    // Parse JSON
    node = yajl_tree_parse( (const char *) data, buff, sizeof(buff) );

    if( NULL == node )
    {
        udpgwlog(LOG_ERR, "JSON parse error: %s", *buff ? buff : "unknown error");
        ret = 1;
        goto done;
    }

    const char *v_devnum  = json_get(node, "devnum", 1);
    const char *v_devname = json_get(node, "devname", 1);
    const char *v_devtype  = json_get(node, "devtype", 1);
    const char *v_param   = json_get(node, "param", 1);
    const char *v_value   = json_get(node, "value", 1);

    if( ! (v_devnum && v_devname && v_devtype && v_param && v_value) )
    {
        ret = 1;
        goto done;
    }

    int nchars = snprintf(buff, sizeof(buff) - 1, "ZWAVE:%s:%s:%s:%s:%s",
                    v_devtype, v_devnum, v_devname, v_param, v_value );

    int res = send( pgwopts->sockfd, (void *) buff, nchars, 0);
    if( -1 == res )
    {
        if( ECONNREFUSED == errno )
        {
            udpgwlog(LOG_ERR, "Connection refused -- check that remote is configured to listen on specified host/port" );
        }
        else
        {
            udpgwlog(LOG_ERR, "Error sending data: %s", strerror(errno));
        }
    }
    else
    {
        udpgwlog(LOG_DEBUG, "Sent data: %s", buff );
    }


done:
    if( NULL != node )
        yajl_tree_free(node);

    return ret;
}


static int
request_loop( struct udp_gw_opts *pgwopts )
{
    size_t num_read;
    int ret = 0;
    char buff[1024];

    // Block waiting for data
    for(;;)
    {
        num_read = read(pgwopts->fifofd, buff, sizeof(buff) - 1);
        if( 0 == num_read )
        {
            udpgwlog(LOG_ERR, "Error, read() from FIFO returned EOF" );
            ret = 1;
            break;
        }
        else if ( -1 == num_read )
        {
            udpgwlog(LOG_ERR, "Failed to read from FIFO: %s", strerror(errno) );
            ret = 1;
            break;
        }
        
        buff[num_read] = '\0';

        if( strncmp(buff, "EXIT", 4) == 0 )
        {
            udpgwlog(LOG_ERR, "Got EXIT, quitting.", strerror(errno));
            break;
        }

        process_data(pgwopts, buff, num_read);
    }

    return ret;
}


int
main(int argc, char *argv[])
{
    struct udp_gw_opts gwopts;

    if( 0 != process_cmdline(argc, argv, &gwopts) )
        return 1;

    // Exit on --help
    if( gwopts.has_help )
        return 0;

    // We must have host, port and fifo file
    if( ! (gwopts.has_address && gwopts.has_port && gwopts.has_fifo) )
    {
        udpgwlog( LOG_ERR, "Must provide --address, --port and --fifo");
        usage();
        return 1;
    }

    if( ! gwopts.foreground )
        daemonise();

    // Open the FIFO
    if( 0 != open_fifo(&gwopts) )
        return 1;

    // Create / bind a UDP socket
    if( 0 != open_socket(&gwopts) )
        return 1;

    // Do real work!
    int ret = request_loop(&gwopts);

    cleanup(&gwopts);

    return ret;
}

