/**************************************************************************
 *                                                                        *
 * tuntopipe.c based on                                                   *
 * simpletun.c                                                            *
 *                                                                        *
 * A helper program encapsulating the specifics of binding to a linux tun *
 * device. To be used as a component.                                     *
 *                                                                        *
 * (c) 2016 Andreas Feldner.                                              *
 * simpletun (C) 2010 Davide Brini.                                       *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>


void my_err(char *msg, ...);

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 65536
#define IPV6PACKET_HEADER_LENGTH 40
#define IPV6PACKET_LENGTH_OFFSET  4
#define IPV6PACKET_PROTOCOL_BYTE_OFFSET  0
#define IPV6PACKET_PROTOCOL_BIT_OFFSET  4

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    my_err("Error writing %d bytes to file descriptor %d\n", n, fd);
  }
  return nwrite;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug) {
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  /* print a time stamp */
  time_t t = time(NULL);
  struct tm *tm = localtime(&t);
  char timebuffer[128];
  if (strftime (timebuffer, sizeof(timebuffer), "%c ", tm) > 0) {
    fputs (timebuffer, stderr);
  }

  /* now print the message including format conversion and va_args */
  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * dump_header: dumps the header of the given packet (buffer) to stderr   *
 **************************************************************************/
void dump_header (char *buffer, int length) {
  int i;
  for (i == 0; i < 40 && i < length; i++) {
    if (i%10 == 0) {
      fputc ('\n', stderr);
    }
    fprintf (stderr, "%x", buffer[i]);
  }
  fputc ('\n', stderr);
}


/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  my_err("Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

/*************************************
 * check if the supplied packet 
 * (buffer and bytes read) are valid
 * IPv6.
 *************************************/
int packet_is_valid_ipv6(char *buffer, int nread) {
  if (nread < IPV6PACKET_HEADER_LENGTH) {
    my_err ("Received too short packet of %d bytes\n", nread);
    dump_header (buffer, nread);
    return 0;
  }
  if (((buffer[IPV6PACKET_PROTOCOL_BYTE_OFFSET] >> IPV6PACKET_PROTOCOL_BIT_OFFSET) & 0x0f) != (char)6) {
    my_err ("Received packet where IP version is not set to 6\n");
    dump_header (buffer, nread);
    return 0;
  }
  uint16_t packetlength = *((uint16_t*)(buffer + IPV6PACKET_LENGTH_OFFSET));
  packetlength = ntohs(packetlength);
  if (packetlength + IPV6PACKET_HEADER_LENGTH != nread) {
    my_err ("Inconsistent length information:\n header information: %d\n read bytes: %d\n", (int)packetlength + IPV6PACKET_HEADER_LENGTH, nread);
    dump_header (buffer, nread);
    return 0;
  }
  return 1;
}

int main(int argc, char *argv[]) {
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int maxfd;
  int nread, nwrite;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";            /* dotted quad IP string */
  int optval = 1;
  socklen_t remotelen;
  unsigned long int tap2pipe = 0, pipe2tap = 0;

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0) {
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg, IFNAMSIZ-1);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0) {
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0') {
    my_err("Must specify interface name!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s with file descriptor %d\n", if_name, tap_fd);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > STDIN_FILENO)?tap_fd:STDIN_FILENO;

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(STDIN_FILENO, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      my_err("Exiting after fatal error in select\n");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)) {
      /* data from tun/tap: just read it and write it to stdout */
      nread = cread(tap_fd, buffer, BUFSIZE);
      if (nread <= 0) {
        my_err("Read %d bytes from tap - exiting\n", nread);
        break;
      } else {
        tap2pipe++;
        /* sort of time tick each 65536 packets */
        if ((tap2pipe & 0xffff) == 1) {
          my_err ("tap2pipe reached %lu and read %d bytes\n", tap2pipe, nread);
        } else  {
          do_debug("TAP2PIPE %lu: Read %d bytes from the tap interface\n", tap2pipe, nread);
        }

        if(packet_is_valid_ipv6(buffer, nread)) {
          /* write packet */
          nwrite = cwrite(STDOUT_FILENO, buffer, nread);
          if (nwrite < 0) {
            my_err("stdout closed, quitting");
            break;
          }
        } else {
          my_err("Dropping invalid packet read from tun device of %d bytes size\n", nread);
        }
      
        do_debug("TAP2PIPE %lu: Written %d bytes to the stdout\n", tap2pipe, nwrite);
      }
    }

    if (FD_ISSET(STDIN_FILENO, &rd_set)) {
      /* data from the pipe: read it, and write it to the tun/tap interface. 

      /* read packet */
      nread = cread(STDIN_FILENO, buffer, BUFSIZE);
      pipe2tap++;
      
      /* again some time-tick function for log file annotation */
      if ((pipe2tap & 0xffff) == 1) {
        my_err ("pipe2tap reached %lu and read %d bytes\n", pipe2tap, nread);
      }
      do_debug("PIPE2TAP %lu: Read %d bytes from STDIN_FILENO\n", pipe2tap, nread);
      if (nread <= 0) {
        my_err ("input pipe closed, exiting\n");
        break;
      } else if (nread > 0) {
        /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
        nwrite = cwrite(tap_fd, buffer, nread);
        do_debug("PIPE2TAP %lu: Written %d bytes to the tap interface\n", pipe2tap, nwrite);
        if (nwrite != nread) {
          my_err ("Failed to write full packet to the tap interface, %d bytes written of %d available\n", nwrite, nread);
        }
      }
    }
  }
  
  return(0);
}
