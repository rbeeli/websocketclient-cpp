import json
import matplotlib.pyplot as plt
import os
import numpy as np


def get_data(directory, agent_name):
    index_json = json.load(open(os.path.join(directory, "index.json"), "r"))
    files = [
        value["reportfile"]
        for key, value in index_json[agent_name].items()
    ]

    # lists to store extracted data
    data = []

    # use glob to find all JSON files in the directory
    for filename in files:
        with open(os.path.join(directory, filename), "r") as file:
            parsed = json.load(file)
            if parsed.get("behavior") != "OK":
                continue
            data.append(
                {
                    "duration": parsed.get("duration", 0),
                    "case": parsed.get("case", 0),
                    "description": parsed.get("description", ""),
                }
            )

    # sorting by case number
    data.sort(key=lambda x: x["case"])

    # filter for duration > 0
    data = [x for x in data if x["duration"] > 0]

    return data


data1 = get_data("/mnt/data/repos/websocketclient-cpp/tests/autobahn/reports/clients/", "ws_client_sync")
data2 = get_data("/mnt/data/repos/websocketclient-cpp/tests/autobahn/reports/clients/", "ws_client_asio")
data3 = get_data("/mnt/data/repos/websocketclient-cpp/tests/autobahn/reports/clients/", "ws_client_coroio")
# data2 = get_data("/mnt/data/repos/boost-tests/autobahn/reports/clients/")



# step 1: fxtract case numbers
case_numbers1 = {d['case'] for d in data1}
case_numbers2 = {d['case'] for d in data2}
case_numbers3 = {d['case'] for d in data3}

# step 2: find the intersection of case numbers
common_cases = case_numbers1.intersection(case_numbers2).intersection(case_numbers3)

# step 3: filter original data by common case numbers
data1 = [d for d in data1 if d['case'] in common_cases]
data2 = [d for d in data2 if d['case'] in common_cases]
data3 = [d for d in data3 if d['case'] in common_cases]




# extract case numbers and durations, assuming both data1 and data2 have the same case numbers
cases = [x["case"] for x in data1]  # extract case numbers
durations1 = np.log([x["duration"] for x in data1])
durations2 = np.log([x["duration"] for x in data2])
durations3 = np.log([x["duration"] for x in data3])

bar_width = 0.7  # width of the bars
index = np.arange(len(cases))  # the label locations

plt.figure(figsize=(14, 8))

plt.bar(
    index - bar_width / 3,
    durations1,
    bar_width / 3,
    label="ws_client_sync",
    color="red",
)
plt.bar(index, durations2, bar_width / 3, label="ws_client_asio", color="blue")
plt.bar(index + bar_width / 3, durations3, bar_width / 3, label="ws_client_coroio", color="cyan")

plt.xlabel("Case Number")
plt.ylabel("Log(Duration)")
plt.title("Log(Duration) by Case Number")
plt.xticks(index, cases)
plt.legend()
plt.show()
