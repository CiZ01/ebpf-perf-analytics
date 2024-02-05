#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 256
#define MAX_INTERFACES 10
#define MAX_SECTIONS 10

typedef struct
{
    char section_name[MAX_LINE_LENGTH];
    char interfaces[MAX_INTERFACES][MAX_LINE_LENGTH];
    int num_interfaces;
} Section;

static int process_config_file(const char *filename, Section *sections, int *num_sections)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        perror("Errore nell'apertura del file");
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    Section current_section;
    current_section.num_interfaces = 0;

    while (fgets(line, sizeof(line), file) != NULL)
    {
        // Rimuove spazi e newline dalla fine della riga
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == ' ' || line[len - 1] == '\n' || line[len - 1] == '\r'))
        {
            line[--len] = '\0';
        }

        // Ignora righe vuote o commenti
        if (len == 0 || line[0] == '#')
        {
            continue;
        }

        // Verifica se è una nuova sezione
        if (line[0] == '[' && line[len - 1] == ']')
        {
            // Salva la sezione corrente
            if (current_section.num_interfaces > 0)
            {
                sections[*num_sections] = current_section;
                (*num_sections)++;
                current_section.num_interfaces = 0;
            }

            // Estrae il nome della sezione
            strncpy(current_section.section_name, line + 1, len - 2);
            current_section.section_name[len - 2] = '\0';
        }
        else
        {
            // splitto la riga di interfacce rispetto alla virgola e aggiungo ogni singola interfaccia alla lista
            char *token = strtok(line, ",");
            while (token != NULL && current_section.num_interfaces < MAX_INTERFACES)
            {
                strncpy(current_section.interfaces[current_section.num_interfaces], token, MAX_LINE_LENGTH);
                current_section.interfaces[current_section.num_interfaces][MAX_LINE_LENGTH - 1] = '\0';
                current_section.num_interfaces++;
                token = strtok(NULL, ",");
            }
        }
    }

    // Salva l'ultima sezione
    if (current_section.num_interfaces > 0 && *num_sections < MAX_SECTIONS)
    {
        sections[*num_sections] = current_section;
        (*num_sections)++;
    }

    fclose(file);
    return 0;
}

int readconf(char *filename, Section *sections, int *num_sections)
{
    *num_sections = 0;
    int err;
    err = process_config_file(filename, sections, num_sections);

    return err;
}
