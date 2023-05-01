with open(r'H:\Cyber Final Project\basic server-client encrypted\share screen test\img_recv', 'rb') as f:
    data_recved = f.read()

with open(r'H:\Cyber Final Project\basic server-client encrypted\share screen test\screenshot', 'rb') as f:
    data_sent = f.read()

def find_index_of_diffs(data1, data2):
    indexes = []
    print(len(data1), len(data2))
    for i in range(len(data1)):
        if data1[i] != data2[i]:
            indexes.append(i)
            
    return indexes

print(len(find_index_of_diffs(data_recved, data_sent)))