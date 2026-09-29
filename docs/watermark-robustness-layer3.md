Layouts: dense, memo, table, figure; 3 trial(s) each = 12 trials per attack, random 64-bit payloads.
Watermark distortion (PSNR vs. the page after headroom remap): mean 35.9 dB.
Machine: macOS-14.5-arm64-arm-64bit-Mach-O, Python 3.13.1.

| Attack | Decoded correctly | Wrong payload | Mean confidence | Min confidence | Mean time |
|---|---|---|---|---|---|
| none (lossless copy) | 12/12 (100%) | 0 | 0.80 | 0.69 | 0.9 s |
| JPEG q90 | 12/12 (100%) | 0 | 0.80 | 0.69 | 0.9 s |
| JPEG q75 | 12/12 (100%) | 0 | 0.80 | 0.68 | 0.8 s |
| JPEG q50 | 12/12 (100%) | 0 | 0.81 | 0.74 | 0.8 s |
| JPEG q30 | 12/12 (100%) | 0 | 0.80 | 0.72 | 0.8 s |
| scale 0.5x (small screenshot) | 12/12 (100%) | 0 | 0.81 | 0.77 | 0.4 s |
| scale 0.75x | 12/12 (100%) | 0 | 0.80 | 0.71 | 0.8 s |
| scale 1.5x | 12/12 (100%) | 0 | 0.80 | 0.70 | 1.0 s |
| rotation 1 deg | 12/12 (100%) | 0 | 0.80 | 0.72 | 0.8 s |
| rotation 5 deg | 12/12 (100%) | 0 | 0.81 | 0.76 | 0.9 s |
| rotation 15 deg | 12/12 (100%) | 0 | 0.81 | 0.76 | 1.1 s |
| rotation 90 deg | 12/12 (100%) | 0 | 0.80 | 0.69 | 0.8 s |
| rotation 180 deg | 12/12 (100%) | 0 | 0.80 | 0.69 | 0.8 s |
| perspective mild (3%) | 12/12 (100%) | 0 | 0.69 | 0.20 | 5.6 s |
| perspective strong (7%) | 9/12 (75%) | 0 | 0.51 | 0.00 | 10.7 s |
| blur sigma 1.0 | 12/12 (100%) | 0 | 0.80 | 0.69 | 0.9 s |
| blur sigma 2.0 | 12/12 (100%) | 0 | 0.78 | 0.64 | 0.9 s |
| noise sigma 8 | 12/12 (100%) | 0 | 0.79 | 0.68 | 0.8 s |
| gamma 0.6 + contrast 0.7 | 12/12 (100%) | 0 | 0.78 | 0.68 | 0.8 s |
| crop 50% area | 12/12 (100%) | 0 | 0.72 | 0.41 | 0.8 s |
| crop 25% area | 11/12 (92%) | 0 | 0.53 | 0.09 | 0.4 s |
| crop 12% area | 7/12 (58%) | 0 | 0.30 | 0.00 | 0.3 s |
| screenshot 0.8x + JPEG 75 | 12/12 (100%) | 0 | 0.79 | 0.70 | 0.8 s |
| crop 50% + rot 5 + JPEG 70 | 12/12 (100%) | 0 | 0.69 | 0.45 | 0.8 s |
| print-and-scan simulation | 12/12 (100%) | 0 | 0.80 | 0.72 | 1.0 s |
| phone photo simulation | 11/12 (92%) | 0 | 0.59 | 0.07 | 14.8 s |

| False-positive check (no watermark) | Detections | Max confidence |
|---|---|---|
| unwatermarked, lossless | 0/12 | 0.04 |
| unwatermarked, phone photo | 0/12 | 0.08 |
