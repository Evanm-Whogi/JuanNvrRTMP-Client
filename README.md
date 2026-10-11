# Juan NVR RTMP client

An RTMP video client for older Guangzhou Juan NVRs, tested with the K8208-W.

## Why this exists

The NVR's Bubble streams work in go2rtc, but playback can lag or become unstable. Its web player used a separate RTMP service on port 80. Standard FFmpeg can connect to that service, but the NVR rejects playback until the client completes a proprietary challenge-response login. This C program performs that login, reassembles RTMP video, writes a video bitstream to stdout, and reconnects after interruptions. go2rtc can read that output and restream it to Frigate.

This is still an NVR stream: the cameras remain connected to the NVR's private wireless network.

## Build and run

Requires a C compiler and OpenSSL development headers:

```sh
gcc -O2 -Wall -Wextra -Wno-deprecated-declarations -o nvr_raw nvr_auth.c -lcrypto
```

Set `NVR_HOST` to the NVR's IPv4 address and `NVR_PASSWORD` to its password in the process environment. The username is `admin`.

```sh
./nvr_raw 0 1 | ffmpeg -f h264 -i pipe:0 -t 10 -f null -  # channel 0 substream
./nvr_raw 0 0 | ffmpeg -f hevc -i pipe:0 -t 10 -f null -  # channel 0 main stream
```

The first argument selects channel `0`–`7`; the second selects main (`0`) or sub (`1`). On the tested camera, main is 1920×1080 HEVC and sub is 640×360 H.264. Check your camera's codec: the NVR's `.264` stream name does not guarantee H.264. Video goes to stdout; status goes to stderr. Audio is not output.

## Frigate / go2rtc

Frigate includes go2rtc. Mount the built binary in the Frigate container and pass `NVR_HOST` and `NVR_PASSWORD` through its environment (for example, a private Compose `env_file`). Add these sources under the existing `go2rtc: streams:` section:

```yaml
go2rtc:
  streams:
    front_yard_main_rtmp:
      - "exec:/usr/local/bin/nvr_raw 0 0"
    front_yard_sub_rtmp:
      - "exec:/usr/local/bin/nvr_raw 0 1"
```

Mount the compiled file at `/usr/local/bin/nvr_raw`, set `GO2RTC_ALLOW_ARBITRARY_EXEC=true` in the Frigate container environment, then recreate the container. Frigate [disables `exec:` sources by default](https://docs.frigate.video/configuration/restream/#security-restricted-stream-sources); enable them only when you trust whoever can edit its configuration.

Point Frigate's `detect` input to `rtsp://localhost:8554/front_yard_sub_rtmp` and its `record` input to `rtsp://localhost:8554/front_yard_main_rtmp`, using `input_args: preset-rtsp-restream`. go2rtc [accepts H.264 and HEVC bitstreams from `exec:` stdout](https://github.com/AlexxIT/go2rtc/blob/master/internal/exec/README.md).