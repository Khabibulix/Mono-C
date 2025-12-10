# ifndef PARSER_H
# define PARSER_H
# include "event.h"

int detect_event_rule(const char *line);
int parse_line(const char *line, Event *ev);


#endif