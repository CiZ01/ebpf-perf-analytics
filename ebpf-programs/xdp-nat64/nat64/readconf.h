#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 100
#define MAX_INTERFACES 10

struct cfg
{
    char name[MAX_LINE_LENGTH];
    char interfaces[MAX_INTERFACES][MAX_LINE_LENGTH];
    int num_interfaces;
    int prog_id;
};

int readconfig(const char *filename, struct cfg *configs, int *num_configs);

int readconfig(const char *filename, struct cfg *configs, int *num_configs)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    char line[MAX_LINE_LENGTH];
    int current_config = -1;
    while (fgets(line, sizeof(line), file) != NULL)
    {
        // Remove newline character if present
        size_t line_length = strlen(line);
        if (line[line_length - 1] == '\n')
        {
            line[line_length - 1] = '\0';
        }
        // Check if it's a section header
        if (line[0] == '[' && line[line_length - 2] == ']')
        {
            current_config++;
            sscanf(line, "[%[^]]", configs[current_config].name);
            configs[current_config].num_interfaces = 0; // Initialize the number of interfaces
        }                                               /* skip comments and blank line */
        else if (line[0] != '#' && line[0] != '\0' && line[0] != '\n')
        {
            // It's an interface line
            if (configs[current_config].num_interfaces < MAX_INTERFACES)
            {
                // split line by comma and store each interface
                char *token = strtok(line, ",");
                while (token != NULL)
                {
                    strcpy(configs[current_config].interfaces[configs[current_config].num_interfaces], token);
                    configs[current_config].num_interfaces++;
                    token = strtok(NULL, ",");
                }
            }
            else
            {
                fprintf(stderr, "Exceeded maximum number of interfaces per router configuration.\n");
                return -1;
            }
        }
    }

    *num_configs = current_config + 1; // Set the number of configurations

    fclose(file);
    return 0;
}
