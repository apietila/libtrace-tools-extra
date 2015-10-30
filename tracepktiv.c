/* This program uses libtrace to calculate packet inter-arrival time stats.
 *
 * Author: Anna-Kaisa Pietilainen
 */
#include <libtrace.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/time.h>
#include <inttypes.h>
#include <lt_inttypes.h>
#include <math.h>

// See: http://www.wikiwand.com/en/Standard_deviation#/Rapid_calculation_methods
#define _stddev(cnt, sum, ssq) sqrt(((double)(cnt)*ssq - sum*sum)/((double)(cnt*(cnt - 1))))

// packets per report (define this or interval)
uint64_t packet_count=UINT64_MAX;
// report interval (in seconds)
double packet_interval=UINT32_MAX;
// number of report periods (default infinite)
uint64_t report_periods=UINT64_MAX;
uint64_t reported=0;

int report_rel_time = 0;

double last_report_ts = 0;

double last_packet_ts = 0;

struct {
  uint64_t count;
  uint64_t bytes;
  double sum;
  double ssq;
  double min;
  double max;
} reports[2];

// as in enum libtrace_direction_t
static int OUT = 0;
static int IN = 1;

static void print_report_hdr() {
  fprintf(stdout, "ts,out pkts,out bytes,out min,out max,out avg,out std,out cv,in pkts,in bytes,in min,in max,in avg,in std,in cv\n");
};

static void reset_report() {
  int dir;
  for (dir = 0; dir < 2; dir++) {  
    reports[dir].count = 0;
    reports[dir].bytes = 0;
    reports[dir].min = -1.0;
    reports[dir].max = -1.0;
    reports[dir].sum = 0;
    reports[dir].ssq = 0;
  }
}

static void print_report(double ts) {
  int dir;
  fprintf(stdout, "%.03f",ts);
  for (dir = 0; dir < 2; dir++) {  
    double mean = 0.0;
    double std = 0.0;
    double cv = 0.0;

    if (reports[dir].count > 2) {
      mean = reports[dir].sum / (reports[dir].count-1);
      std = _stddev((reports[dir].count-1), reports[dir].sum, reports[dir].ssq);
      if (mean > 0)
	cv = std / mean;
    }

    fprintf(stdout, ",%" PRIu64 ",%" PRIu64 ",%f,%f,%f,%f,%f", 
	    reports[dir].count,
	    reports[dir].bytes,
	    reports[dir].min,
	    reports[dir].max,
	    mean,std,cv);
  }
  fprintf(stdout, "\n");
  reset_report();
  ++reported;
}

static void per_packet(libtrace_packet_t *packet)
{
    int dir;
    double ts, ia;

    ts = trace_get_seconds(packet);
    dir = trace_get_direction(packet);   

    if (last_report_ts == 0) {
       last_report_ts = ts;
    }

    // time interval based reporting
    while (packet_interval != UINT32_MAX && 
	   last_report_ts+packet_interval<ts && 
	   (report_periods == UINT64_MAX || reported < report_periods)) {
      last_report_ts+=packet_interval;
      if (report_rel_time) {
	print_report(packet_interval);
      } else {
	print_report(last_report_ts);
      }
    }
    
    if (dir == OUT || dir == IN) {
      if (last_packet_ts > 0) {
	ia = (ts - last_packet_ts) * 1000.0; // in ms
	  reports[dir].sum += ia;
	  reports[dir].ssq += (ia*ia);
	  if (reports[dir].min < 0 || ia < reports[dir].min)
	    reports[dir].min = ia;
	  if (reports[dir].max < 0 || ia > reports[dir].max)
	    reports[dir].max = ia;
      }
      reports[dir].count++;
      reports[dir].bytes += trace_get_wire_length(packet);
    }

    if (packet_count != UINT64_MAX &&  
	(reports[OUT].count+reports[IN].count) > 0 && 
	(reports[OUT].count+reports[IN].count)%packet_count == 0 &&
	(report_periods == UINT64_MAX || reported < report_periods)) {
      if (report_rel_time) {
	print_report(ts-last_report_ts);
      } else {
	print_report(ts);
      }
      last_report_ts = ts;
    }

    last_packet_ts = ts;
}

static void usage(char *argv0)
{
  fprintf(stderr,"usage: %s [-i iv| --interval] [-c packets| --count] [-e periods| --exit] [-r | --relative] [ --filter | -f bpfexp ]\n\t\t[ --help | -h ] [ --libtrace-help | -H ] libtraceuri...\n",argv0);
}

int main(int argc, char *argv[]) {
  libtrace_t *trace;
  libtrace_packet_t *packet;
  libtrace_filter_t *filter=NULL;
  uint64_t f;
  
  while(1) {
    int option_index;
    struct option long_options[] = {
      { "filter",	1, 0, 'f' },
      { "interval",     1, 0, 'i' },
      { "count",        1, 0, 'c' },
      { "exit",         1, 0, 'e' },			
      { "relative",     0, 0, 'r' },
      { "help",	        0, 0, 'h' },
      { "libtrace-help",0, 0, 'H' },
      { NULL,		0, 0, 0 }
    };
    
    int c= getopt_long(argc, argv, "c:e:f:i:hHr",
		       long_options, &option_index);
    
    if (c==-1)
      break;
    
    switch (c) {
    case 'f':
      filter=trace_create_filter(optarg);
      break;
    case 'i':
      packet_interval=atof(optarg);
      packet_count=UINT64_MAX; // make sure only one is defined
      break;
    case 'c':
      packet_count=atoi(optarg);
      packet_interval=UINT32_MAX; // make sure only one is defined
      break;
    case 'e':
      report_periods=atoi(optarg);
      break;      
    case 'r':
      report_rel_time = 1;
      break;
    case 'H':
      trace_help();
      return 1;
    default:
      fprintf(stderr,"Unknown option: %c\n",c);
      /* FALL THRU */
    case 'h':
      usage(argv[0]);
      return 1;
    }
  }

  if (optind>=argc) {
    fprintf(stderr,"Missing input uri\n");
    usage(argv[0]);
    return 1;
  }

  while (optind<argc) {
    fprintf(stderr,"processsing: '%s'\n", argv[optind]);            
    trace = trace_create(argv[optind]);
    ++optind;

    if (trace_is_err(trace)) {
      trace_perror(trace,"Opening trace file");
      return 1;
    }
    
    if (filter)
      if (trace_config(trace,TRACE_OPTION_FILTER,filter)) {
	trace_perror(trace,"ignoring: ");
      }
    
    if (trace_start(trace)) {
      trace_perror(trace,"Starting trace");
      trace_destroy(trace);
      return 1;
    }

    packet = trace_create_packet();
    
    print_report_hdr();
    reset_report();
    last_report_ts = 0;
    last_packet_ts = 0;

    while (trace_read_packet(trace,packet)>0) {
      per_packet(packet);
      if (report_periods != UINT64_MAX && reported >= report_periods) {
	break;
      }
    }

    // remaining pkts (or all if no period set)
    if ((reports[OUT].count+reports[IN].count) > 0 || 
	(packet_interval == UINT32_MAX && packet_count == UINT64_MAX)) {
      double ts = trace_get_seconds(packet);
      if (report_rel_time) {
	print_report(ts-last_report_ts);
      } else {
	print_report(ts);
      }
    }

    trace_destroy_packet(packet);
    
    if (trace_is_err(trace)) {
      trace_perror(trace,"Reading packets");
    }

    // some stats
    f=trace_get_received_packets(trace);
    if (f!=UINT64_MAX)
      fprintf(stderr,"%" PRIu64 " packets on input\n",f);
    f=trace_get_filtered_packets(trace);
    if (f!=UINT64_MAX)
      fprintf(stderr,"%" PRIu64 " packets filtered\n",f);
    f=trace_get_dropped_packets(trace);
    if (f!=UINT64_MAX)
      fprintf(stderr,"%" PRIu64 " packets dropped\n",f);
    f=trace_get_accepted_packets(trace);
    if (f!=UINT64_MAX)
      fprintf(stderr,"%" PRIu64 " packets accepted\n",f);
    
    trace_destroy(trace);
  }
  
  return 0;
}
