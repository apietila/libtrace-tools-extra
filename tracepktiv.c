/* This program uses libtrace to produce packet inter-arrival time stats
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

double packet_interval=UINT32_MAX;

double next_print_ts=0;
double last_packet_ts=0;

uint64_t in_ia_count=0;
double in_ia_sum=0.0;
double in_ia_ssq=0.0;
double in_ia_min=0.0;
double in_ia_max=0.0;

uint64_t out_ia_count=0;
double out_ia_sum=0.0;
double out_ia_ssq=0.0;
double out_ia_min=-1.0;
double out_ia_max=-1.0;

static void print_hdr() {
  fprintf(stdout, "ts,in pkts,in min,in max,in avg,in std,in cv,out pkts,out min,out max,out avg,out std,out cv\n");
};

static void print_stats(double ts) {
  double in_mean = 0.0;
  double in_std = 0.0;
  double in_cv = 0.0;
  double out_mean = 0.0;
  double out_std = 0.0;
  double out_cv = 0.0;
  
  if (in_ia_count > 1) {
    in_mean = in_ia_sum / in_ia_count;
    in_std = _stddev(in_ia_count, in_ia_sum, in_ia_ssq);
  }
  if (out_ia_count > 1) {
    out_mean = out_ia_sum / out_ia_count;
    out_std = _stddev(out_ia_count, out_ia_sum, out_ia_ssq);
  }

  if (in_mean > 0)
    in_cv = in_std / in_mean;
  if (out_mean > 0)
    out_cv = out_std / out_mean;
  
  fprintf(stdout, "%.03f,%" PRIu64 ",%f,%f,%f,%f,%f,%" PRIu64 ",%f,%f,%f,%f,%f\n",ts,in_ia_count,in_ia_min,in_ia_max,in_mean,in_std,in_cv,out_ia_count,out_ia_min,out_ia_max,out_mean,out_std,out_cv);

  in_ia_count=0;
  in_ia_sum=0.0;
  in_ia_ssq=0.0;
  in_ia_min=-1.0;
  in_ia_max=-1.0;

  out_ia_count=0;
  out_ia_sum=0.0;
  out_ia_ssq=0.0;
  out_ia_min=-1.0;
  out_ia_max=-1.0;
}

static void per_packet(libtrace_packet_t *packet)
{
    int dir;
    double ts, ia;

    ts = trace_get_seconds(packet);
    dir = trace_get_direction(packet);   

    if (next_print_ts == 0) {
       next_print_ts = ts+packet_interval;
    }
                                
    while (packet_interval != UINT32_MAX && next_print_ts<ts) {
      print_stats(next_print_ts);
      next_print_ts+=packet_interval;
    }
    
    if (last_packet_ts > 0) {
	ia = ts - last_packet_ts;    

	if (dir == TRACE_DIR_OUTGOING) {
	  out_ia_count++;
	  out_ia_sum += ia;
	  out_ia_ssq += (ia * ia);
	  if (out_ia_min < 0 || ia < out_ia_min)
	    out_ia_min = ia;
	  if (out_ia_max < 0 || ia > out_ia_max)
	    out_ia_max = ia;
	    
	} else if (dir == TRACE_DIR_INCOMING) {
	  in_ia_count++;
	  in_ia_sum += ia;
	  in_ia_ssq += (ia * ia);
	  if (in_ia_min < 0 || ia < in_ia_min)
	    in_ia_min = ia;
	  if (in_ia_max < 0 || ia > in_ia_max)
	    in_ia_max = ia;
	}
    }
    
    last_packet_ts = ts;
}

static void usage(char *argv0)
{
	fprintf(stderr,"usage: %s [-i iv| --interval] [ --filter | -f bpfexp ]\n\t\t[ --help | -h ] [ --libtrace-help | -H ] libtraceuri...\n",argv0);
}

int main(int argc, char *argv[])
{
	libtrace_t *trace;
	libtrace_packet_t *packet;
	libtrace_filter_t *filter=NULL;
	
	packet_interval = 10; // default interval

	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",		1, 0, 'f' },
			{ "interval",		1, 0, 'i' },
			{ "help",		0, 0, 'h' },
			{ "libtrace-help",	0, 0, 'H' },
			{ NULL,			0, 0, 0 }
		};

		int c= getopt_long(argc, argv, "f:i:hH",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'f':
				filter=trace_create_filter(optarg);
				break;
			case 'i':
				packet_interval=atof(optarg);
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

		print_hdr();
		next_print_ts=0;
		last_packet_ts=0;

		while (trace_read_packet(trace,packet)>0) {
			per_packet(packet);
		}
	        print_stats(last_packet_ts);

		trace_destroy_packet(packet);

		if (trace_is_err(trace)) {
			trace_perror(trace,"Reading packets");
		}

		trace_destroy(trace);
	}

	return 0;
}
