from datetime import datetime
import csv
import json
import time

def Write_Log(filename, log):
    with open(filename, 'a') as f:
        json.dump(log, f)
        f.write("\n")
    f.close()


def Read_CSV():
    global airodumpCSV
    global dataReader
    global listData
    global apStart
    global clientStart
    global lineCount

    apStart = 0
    clientStart = 0
    lineCount = 0
    while[1]:
        try:
            airodumpCSV = open("airodump-01.csv")
            dataReader = csv.reader(airodumpCSV)
            listData = list(dataReader)
            break
        except:
            print "[~] Waiting for file.."
            time.sleep(3)

    apList = [" Cipher", " Authentication"]
    clientList = ["Station MAC", " Probed ESSIDs"]
    ## Find where the APs and Clients are
    for row in listData:
        # If someone makes their ESSID "Cipher Authentication" this will
        # obviously not work, but that is unlikely..
        if all(x in row for x in apList):
            apStart = lineCount + 1
        if all(x in row for x in clientList):
            clientStart = lineCount + 1
        lineCount += 1

def InsertUpdate_AccessPointsToList():
    for x in range(apStart, clientStart-2):
        ## Is this a new AP?
        if not any (d['BSSID'] == listData[x][0].strip() for d in APs):
            with open("json.log", 'w') as f:
                json.dumps(listData[x], f)
            f.close()
            newAP = {   "_time":datetime.now().isoformat("T"),
                    "Action":"Discovered",
                    "Class":"Access_point",
                    "ESSID":listData[x][13].strip(),
                    "BSSID":listData[x][0].strip(),
                    "Channel":listData[x][3].strip(),
                    "Authentication":listData[x][5].strip(),
                    "Power":listData[x][6].strip()
                }
            APs.append(newAP)
            Write_Log(APFile, newAP)
        else: ## Has anything changed with the AP?
            updateActions = []
            for ap in APs:
                if ap['BSSID'] == listData[x][0].strip():
                    if ap['ESSID'] != listData[x][13].strip():
                        updateActions.append("ESSID_Update")
                    if ap['Authentication'] != listData[x][5].strip():
                        updateActions.append("Authentication_Update")
                    if len(updateActions) > 0:
                        for updateAction in updateActions:
                            updateAP = {    "_time":datetime.now().isoformat("T"),
                                            "Action":updateAction,
                                            "Class":"Access_point",
                                            "ESSID":listData[x][13].strip(),
                                            "BSSID":listData[x][0].strip(),
                                            "Channel":listData[x][3].strip(),
                                            "Authentication":listData[x][5].strip(),
                                            "Power":listData[x][6].strip()
                                        }
                            Write_Log(APFile, updateAP)
                        APs.remove(ap)
                        # Even though this will only store the last of the possible updates, it
                        # has already logged all changes, which, ultimatley is what we care about.
                        APs.append(updateAP)


def InsertUpdate_ClientsToList():
    for x in range(clientStart, lineCount-1):
        apQuery = []
        for y in range(6, len(listData[x])):
            if listData[x][y] != "":
                apQuery.append({"ESSID":listData[x][y].strip()})
        if not any (d['ClientMAC'] == listData[x][0].strip() for d in Clients):
            newClient = {   "_time":datetime.now().isoformat("T"),
                            "Action":"Discovered",
                            "Class":"Client",
                            "ClientMAC":listData[x][0].strip(),
                            "ConnectedBSSID":listData[x][5].strip(),
                            "ProbedESSIDs":apQuery
                        }
            Clients.append(newClient)
            Write_Log(ClientFile, newClient)
        else:
            updateActions = []
            for client in Clients:
                if client['ClientMAC'] == listData[x][0].strip():
                    if client['ConnectedBSSID'].strip() != listData[x][5].strip():
                        print "Hit"
                        updateActions.append("Client_Association")
                    apQuery = []
                    for y in range(6, len(listData[x])):
                        if listData[x][y] != "":
                            apQuery.append({"ESSID":listData[x][y].strip()})
                    if client['ProbedESSIDs'] != apQuery:
                        updateActions.append("ProbedESSID_Change")
                    if len(updateActions) > 0:
                        print updateActions
                        for updateAction in updateActions:
                            print "updating"
                            updateClient = {    "_time":datetime.now().isoformat("T"),
                                                "Action":updateAction,
                                                "Class":"Client",
                                                "ClientMAC":listData[x][0].strip(),
                                                "ConnectedBSSID":listData[x][5].strip(),
                                                "ProbedESSIDs":apQuery
                                            }
                            Write_Log(ClientFile, updateClient)
                        Clients.remove(client)
                        # Even though this will only store the last of the possible updates, it
                        # has already logged all changes, which, ultimatley is what we care about.
                        Clients.append(updateClient)

def Remove_AccessPointsFromList():
    for x in APs:
        if not any(x['BSSID'] == listData[a][0].strip() for a in range(apStart, clientStart-2)):
            deadAP = {  "_time":datetime.now().isoformat("T"),
                        "Action":"SignalLost",
                        "Class":"Access_point",
                        "ESSID":x['ESSID'],
                        "BSSID":x['BSSID'],
                        "Channel":x['Channel'],
                        "Authentication":x['Authentication'],
                        "Power":x['Power']
                    }
            Write_Log(APFile, deadAP)
            APs.remove(x)

def Remove_ClientsFromList():
    for x in Clients:
        if not any(x['ClientMAC'] == listData[a][0].strip() for a in range(clientStart, lineCount-1)):
            lostClient = {      "_time":datetime.now().isoformat("T"),
                                "Action":"Client_Out_of_Range",
                                "Class":"Client",
                                "ClientMAC":x['ClientMAC'],
                                "ConnectedBSSID":x['ConnectedBSSID'],
                                "ProbedESSIDs":x['ProbedESSIDs']
                            }
            Write_Log(ClientFile, lostClient)
            Clients.remove(x)

def main():
    global APs
    global Clients
    global APFile
    global ClientFile
    print '[~] Starting airodump csv to json log'

    APFile = "AccessPoints.log"
    ClientFile = "Clients.log"
    stdErr = "python.log"
    APs = []
    Clients = []
    Quit = 0

    while [1]:
        try:
            Read_CSV()
            InsertUpdate_AccessPointsToList()
            InsertUpdate_ClientsToList()
            Remove_AccessPointsFromList()
            Remove_ClientsFromList()
            time.sleep(3)
        except KeyboardInterrupt:
            print "[~] KeyboardInterrupt Detected... Exiting"
            exit()
        except Exception as err:
            print "[!] An error has occured!"
            print(traceback.format_exc())
            pass

if __name__ == '__main__':
    main()
