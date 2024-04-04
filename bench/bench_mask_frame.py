import os
import re
import pandas as pd
import matplotlib.pyplot as plt


def skip_to(fle, line, **kwargs):
    if os.stat(fle).st_size == 0:
        raise ValueError("File is empty")
    with open(fle) as f:
        pos = 0
        cur_line = f.readline()
        while not cur_line.startswith(line):
            pos = f.tell()
            cur_line = f.readline()
        f.seek(pos)
        return pd.read_csv(f, **kwargs)


arch = "arm"
# arch = "x86"
df = skip_to(f"bench_mask_frame_{arch}.csv", "name,", sep=",")


def extract_name_number(s):
    match = re.search(r"<(\w+)>/(\d+)", s)
    if match:
        return match.group(1), int(match.group(2))
    return None, None


# Applying the function
df[["name", "bytes"]] = (
    df["name"].apply(lambda x: extract_name_number(x)).apply(pd.Series)
)
df = df[["name", "bytes", "cpu_time"]]

plt.figure(figsize=(10, 6))
for name, group in df.groupby("name"):
    plt.plot(group["bytes"], group["cpu_time"], label=name, marker="o")
plt.xlabel("Bytes")
plt.ylabel("CPU Time")
plt.xscale("log")
plt.yscale("log")
plt.title(f"Payload masking CPU time for Different Methods ({arch})")
plt.legend()
plt.grid(True)
plt.show()
