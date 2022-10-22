# otbn_pq

## Synthesize OTBN-PQ Standalone

With the following commands a build script for standalone test synthesis for the OTBN-PQ for Vivado is generated:
```console
$ fusesoc --cores-root . run --flag=fileset_top --target=sim --no-export --setup aisec:ip:otbn_pq:0.1
$ cd build/aisec_ip_otbn_pq_0.1/synth-vivado/
$ . /tools/Xilinx/Vivado/20XX.XX/settings64.sh
$ vivado
```

Within Vivado execute the following commands to generate the project:
```console
source aisec_ip_otbn_pq_0.1.tcl
```

### Results
Test synthesis results (Vivado 2020.2)

|                          | LUTs          | FFs           | BRAMs         | DSP           | 
| -------------------------|:-------------:|:-------------:|:-------------:|:-------------:|
| OTBN-PQ                  | 33,555        | 13,875        | 10.5          | 49            |


## Simulate OTBN-PQ Standalone

With the following commands a build script for standalone RTL-simulation environnemnt for the OTBN-PQ for Vivado is generated:
```console
$ fusesoc --cores-root . run --flag=fileset_top --target=synth --no-export --setup aisec:ip:otbn_pq:0.1
$ cd build/aisec_ip_otbn_pq_0.1/sim-vivado/
$ . /tools/Xilinx/Vivado/20XX.XX/settings64.sh
$ vivado
```

Within Vivado execute the following commands to generate the project and configure the simulator:

```console
source aisec_ip_otbn_pq_0.1.tcl
set_property top tb_otbn [get_filesets sim_1]
set_property top_lib xil_defaultlib [get_filesets sim_1]
set_property -name {xsim.simulate.runtime} -value {250000ns} -objects [get_filesets sim_1]
```

### Results
Simulation results (Vivado 2020.2 - 22.10.2022)

| Test                     | CC            | Errors  |
| -------------------------|:-------------:| -----:|
| Kyber-NTT                | 1,454         | 0 |
| Kyber-NTT (unrolled)     | 1,038         | 0 |
| Kyber-INTT 	           | 1,726         | 0 |
| Kyber-INTT (unrolled)    | 1,302         | 0 |
| Kyber-BaseMul            | 1,448         | 0 |
| Dilithium-NTT            | 1,972         | 0 |
| Dilithium-NTT (unrolled) | 1,168         | 0 |
| Dilithium-INTT           | 2,244         | 0 |
| Dilithium-INTT (unrolled)| 1,430         | 0 |
| Dilithium-Mul            | 768           | 0 |
| Falcon-512-NTT           | 5,172         | 0 |
| Falcon-512-INTT          | 5,712         | 0 |
| Falcon-512-Mul           | 1,512         | 0 |
| Falcon-1024-NTT          | 13,598        | 0 |
| Falcon-1024-INTT         | 14,652        | 0 |
| Falcon-1024-Mul          | 2,2992        | 0 |

