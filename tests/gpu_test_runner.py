# -*- coding: utf-8 -*-
import subprocess
import time
import psutil

def is_gpu_idle(threshold=10):
    try:
        result = subprocess.run(['nvidia-smi', '--query-gpu=utilization.gpu', '--format=csv,noheader,nounits'], stdout=subprocess.PIPE)
        gpu_usages = result.stdout.decode('utf-8').strip().split('\n')
        for i, usage in enumerate(gpu_usages):
            if float(usage) < threshold:
                print(f"GPU {i} is idle with usage {usage}%.")
                return i  
        return None  
    except Exception as e:
        print(f"Failed to get GPU usage: {e}")
        return None

def run_tests(test_commands, output_file):
    for command in test_commands:
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            with open(output_file, 'a') as f:
                f.write(f"Test run for command {command} at {time.ctime()}\n")
                f.write(result.stdout.decode('utf-8'))
                f.write(result.stderr.decode('utf-8'))
                f.write('\n\n')
        except Exception as e:
            print(f"Failed to run test {command}: {e}")

def main():
    test_groups = [
        (['./add_inplace', './add_plain', './add_plain_inplace', './add', './add_many'], 'add_op.txt'),
        (['./sub_inplace', './sub_plain', './sub_plain_inplace', './sub'], 'sub_op.txt'),
        (['./multi_inplace', './multi_plain', './multi_plain_inplace', './multi'], 'multi_op.txt'),
        (['./negation_inplace', './negation_inplace'], 'negation_op.txt')
    ]

    while True:
        if is_gpu_idle():
            print("GPU is idle, running tests...")
            for test_commands, output_file in test_groups:
                run_tests(test_commands, output_file)
            break
        else:
            print("GPU is busy, waiting...")
        
        time.sleep(60)

if __name__ == '__main__':
    main()