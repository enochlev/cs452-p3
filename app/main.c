#include <stdio.h>
#include "../src/lab.h"

int main(int argc, char **argv)
{
  
  char* env = get_prompt("MY_PROMPT");

  parse_args(argc, argv);

  struct shell s;
  s.prompt = env;

  sh_init(&s);
  sh_destroy(&s); 
  return 0;
}
