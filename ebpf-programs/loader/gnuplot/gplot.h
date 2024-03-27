#ifndef GPLOT_H
#define GPLOT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// TODO improve error handling

struct gnuplot_cfg
{
    char filename[256];
    char title[32];
    int poll_interval;
    FILE *fp;
    /*     char xlabel[32];
        char ylabel[32];
        int min_y;
        int max_y;*/
    int min_x;
    int max_x;
};

FILE *dat_file;
struct gnuplot_cfg __cfg;
FILE *gnuplotPipe;

void gplot_close()
{
    // close gnuplot
    /* if (gnuplotPipe)
        pclose(gnuplotPipe);
    this block the program*/

    fclose(dat_file);
    return;
}

/*
 * Initialize gnuplot
 * @param filename: name of the file to write the data
 * @return 0 if success, 1 if error
 *
 */
int gplot_init(struct gnuplot_cfg *cfg)
{
    dat_file = fopen(cfg->filename, "w");
    if (dat_file == NULL)
    {
        return 1;
    }

    // open GNUplot
    gnuplotPipe = popen("gnuplot -persist", "w");
    if (gnuplotPipe == NULL)
    {
        gplot_close();
        return 1;
    }

    memcpy(&__cfg, cfg, sizeof(struct gnuplot_cfg));
    // simple settings
    fprintf(gnuplotPipe, "set encoding utf8\n");
    fprintf(gnuplotPipe, "set term wxt persist\n");
    fprintf(gnuplotPipe, "set datafile separator \" \"\n"); // sometimes GNUplot forgets the separator

    // set x and y range
    fprintf(gnuplotPipe, "set yrange [%d:%d]\n", 0, 150);
    fprintf(gnuplotPipe, "set xrange [\"0\":\"100\"]\n");

    /*     fprintf(gnuplotPipe, "set xdata time\n");
        fprintf(gnuplotPipe, "set timefmt \"%%H:%%M:%%S\"\n");
        fprintf(gnuplotPipe, "set xrange [\"00:00:00\":\"24:00:00\"]\n");
        fprintf(gnuplotPipe, "set xtics format \"%%H:%%M:%%S\"\n");
     */
    // pretty settings
    fprintf(gnuplotPipe, "set title \"%s\"\n", __cfg.title);
    /*     fprintf(gnuplotPipe, "set xlabel \"Time\"\n");
        fprintf(gnuplotPipe, "set ylabel \"Value\"\n"); */

    // set fp
    cfg->fp = dat_file;
    return 0;
}

/*
 * Plot data
 */
void gplot_plot_poll()
{
    // start plot and polling
    while (1)
    {
        // fprintf(gnuplotPipe, "%s\n", "e");
        fprintf(gnuplotPipe, "set autoscale\n");
        fprintf(gnuplotPipe, "plot \"%s\" using 1:2 with lines\n", __cfg.filename);
        fflush(gnuplotPipe);

        // needed to start/update the window
        sleep(__cfg.poll_interval);
    }
    return;
}

#endif