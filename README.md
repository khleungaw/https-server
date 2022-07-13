## About
A C++ implementation of a static https/1.1 server that handles the C10K problem.
* Uses Epoll and OpenSSL 
* Utilizes non-blocking I/O with EPOLLET and EPOLLONESHOT
* Have multiple threads to handle multiple connections

## Usage
```bash
mkdir build && cd build
cmake ..
make
./server <httpPort> <httpsPort> <certFile> <keyFile> <publicFolderPath> <threadPoolSize> <domain>
```

## Benchmark
Tests were done using [plow](https://github.com/six-ddc/plow):
```bash
# Environment: WSL2 Ubuntu with 4GB of RAM and 2 processors (Ryzen 3500X)

.\plow -c 10000 -d 30s -k https://[]:4430

Benchmarking https://[]:4430 for 30s using 10000 connection(s).
@ Real-time charts is listening on http://[::]:18888

Summary:
  Elapsed     30.005s
  Count       1330855
    2xx       1315329
  RPS       44354.090
  Reads    26.371MB/s
  Writes    3.717MB/s

Error:
  80     "dial tcp4 []:4430: i/o timeout"
  15446  "dialing to the given TCP address timed out"

Statistics    Min      Mean      StdDev       Max
  Latency     0s     177.254ms  1.314677s  29.04253s
  RPS       3561.01  44371.58   10046.79   55714.12

Latency Percentile:
  P50         P75        P90        P95        P99       P99.9       P99.99
  56.256ms  90.397ms  126.554ms  152.848ms  3.041874s  25.161704s  26.791311s

Latency Histogram:
  133.409ms   1301021  97.76%
  1.283015s     28845   2.17%
  22.598087s      174   0.01%
  25.835554s      491   0.04%
  26.636325s      254   0.02%
  26.804356s       21   0.00%
  27.803986s       34   0.00%
  28.786299s       15   0.00%
```