mount 감지 구현 완료,

후킹대상 시스템콜:__x64_sys_mount

$sudo ./mount_Monitor_user

필터링 조건문
   struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

작동결과
  로그
  $sudo mount --bind /host /mnt
[MOUNT] PID=161827 COMM=mount SOURCE= TARGET= FLAGS=0x48
  
  $sudo docker run busybox echo "Hello from BusyBox!"  
[MOUNT] PID=1468 COMM=dockerd SOURCE= TARGET= FLAGS=0x48
[MOUNT] PID=1468 COMM=dockerd SOURCE= TARGET= FLAGS=0x48
[MOUNT] PID=1468 COMM=dockerd SOURCE= TARGET= FLAGS=0x48
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=161761 COMM=runc:[2:INIT] SOURCE= TARGET= FLAGS=0x0
[MOUNT] PID=1468 COMM=dockerd SOURCE= TARGET= FLAGS=0x48
