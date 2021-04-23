#!/usr/bin/python
__author__ = "Rodrigo E. Quintanilla"
__version__ = "0.1"

from collections import OrderedDict
import sys, time, os, argparse, xlsxwriter, re

debug = False
filter_action = ""
split_character = " "
max_items_show = 50
reports_folder = "REPORTS"
file_path = ""
output_format = ""
csv_filename  = file_path.split(".")[0] + "_" + time.strftime("%Y-%m-%d_%H-%M") + ".csv"
xslx_filename = file_path.split(".")[0] + "_" + time.strftime("%Y-%m-%d_%H-%M") + ".xlsx"

"""                 
EJEMPLO DE LOGS QUE ACEPTA
date=2017-06-27 time=12:20:12 itime=1498558581 logver=52 logid=13 type=traffic subtype=forward level=notice vd=root devid=1 action=deny trandisp=noop srcip= srcport=57855 dstip=2.22.71.27 dstport=443 service=HTTPS proto=6 duration=0 policyid=11 sentbyte=0 rcvdbyte=0 srcintf=datos dstintf=switch sessionid=7345063 app=HTTPS appcat=Not.Scanned dstcountry=Europe srccountry=Reserved crscore=30 craction=131072 poluuid=de4f8aa6-6b8e-51e6-d875-2ba57b545a9a threats={blocked-connection} threatlvls={3} threattyps={blocked-connection} threatcnts={1} threatwgts={30} crlevel=high
date=2017-06-27 time=12:20:12 itime=1498558581 logver=52 logid=13 type=traffic subtype=forward level=notice vd=root devid=1 action=accept trandisp=noop srcip= srcport=61210 dstip=121.253.61.68 dstport=443 service=HTTPS proto=6 duration=0 policyid=11 sentbyte=0 rcvdbyte=0 srcintf=datos dstintf=wan sessionid=7345062 app=HTTPS appcat=Not.Scanned dstcountry="United States" srccountry=Reserved crscore=30 craction=131072 poluuid=de4f8aa6-6b8e-51e6-d875-2ba57b545a9a threats={blocked-connection} threatlvls={3} threattyps={blocked-connection} threatcnts={1} threatwgts={30} crlevel=high
date=2017-06-27 time=12:20:11 itime=1498558581 logver=52 logid=13 type=traffic subtype=forward level=notice vd=root devid=2 action=deny trandisp=noop srcip= srcport=61209 dstip=40.113.22.47 dstport=443 service=HTTPS proto=6 duration=0 policyid=11 sentbyte=0 rcvdbyte=0 srcintf=datos dstintf=switch-wan sessionid=7345059 app=HTTPS appcat=Not.Scanned dstcountry=Ireland srccountry=Reserved crscore=30 craction=131072 poluuid=de4f8aa6-6b8e-51e6-d875-2ba57b545a9a threats={blocked-connection} threatlvls={3} threattyps={blocked-connection} threatcnts={1} threatwgts={30} crlevel=high
date=2017-06-27 time=12:20:11 itime=1498558581 logver=52 logid=13 type=traffic subtype=forward level=notice vd=root devid=3 action=close trandisp=noop srcip= srcport=3880 dstip=10.69.132.153 dstport=88 service=KERBEROS proto=6 duration=5 policyid=10 sentbyte=1796 rcvdbyte=1790 sentpkt=6 rcvdpkt=6 srcintf=data dstintf=switch-wan sessionid=7345035 app=KERBEROS appcat=Not.Scanned dstcountry=Reserved srccountry=Reserved poluuid=de3d4670-6b8e-51e6-2c79-5bcb63e29036
date=2017-06-27 time=12:20:10 itime=1498558579 logver=52 logid=13 type=traffic subtype=forward level=notice vd=root devid=3 action=deny trandisp=noop srcip= srcport=54206 dstip=50.77.226.218 dstport=443 service=HTTPS proto=6 duration=0 policyid=11 sentbyte=0 rcvdbyte=0 srcintf=datos dstintf=switch-wan sessionid=7345055 app=HTTPS appcat=Not.Scanned dstcountry=Ireland srccountry=Reserved crscore=30 craction=131072 poluuid=de4f8aa6-6b8e-51e6-d875-2ba57b545a9a threats={blocked-connection} threatlvls={3} threattyps={blocked-connection} threatcnts={1} threatwgts={30} crlevel=high
"""

banner = """
-----------------------------------------------------
  ______         _   _ _____                         
 |  ____|       | | (_)  __ \                        
 | |__ ___  _ __| |_ _| |__) |_ _ _ __ ___  ___ _ __ 
 |  __/ _ \| '__| __| |  ___/ _` | '__/ __|/ _ \ '__|
 | | | (_) | |  | |_| | |  | (_| | |  \__ \  __/ |   
 |_|  \___/|_|   \__|_|_|   \__,_|_|  |___/\___|_|

------------------------------------------------------
 Program: FortiParser v0.1
 Author:  Rodrigo E. Quintanilla
 -----------------------------------------------------
"""


# Cada regla del firewall tiene asocada unos accesos
class RuleID(object):

    def __init__(self, id, dstport, proto, dstip, srcip, srcintf, dstintf, service):
        self.id = int(id)
        self.srcintf = {}
        self.dstintf = {}
        self.services = {}
        self.dstports_udp = {}
        self.dstports_tcp = {}
        self.dstips = {}
        self.srcips = {}

        self.countSrcIntf(srcintf)
        self.countDstIntf(dstintf)
        self.countService(service)
        self.countPort(dstport, proto)
        self.countDstIP(dstip)
        self.countSrcIP(srcip)


    def countTCPPort(self, port):
        if self.dstports_tcp.__contains__(port):
            self.dstports_tcp[port] += 1
        else:
            self.dstports_tcp[port] = 1

    def countUDPPort(self, port):
        if self.dstports_udp.__contains__(port):
            self.dstports_udp[port] += 1
        else:
            self.dstports_udp[port] = 1

    def countPort(self, port, protocol):
        if protocol == "6":
            self.countTCPPort(port)
        if protocol == "17":
            self.countUDPPort(port)

    def countDstIP(self, dstip):
        if self.dstips.__contains__(dstip):
            self.dstips[dstip] += 1
        else:
            self.dstips[dstip] = 1

    def countSrcIP(self, srcip):
        if self.srcips.__contains__(srcip):
            self.srcips[srcip] += 1
        else:
            self.srcips[srcip] = 1

    def countSrcIntf(self, srcintf):
        if self.srcintf.__contains__(srcintf):
            self.srcintf[srcintf] += 1
        else:
            self.srcintf[srcintf] = 1

    def countDstIntf(self, dstintf):
        if self.dstintf.__contains__(dstintf):
            self.dstintf[dstintf] += 1
        else:
            self.dstintf[dstintf] = 1

    def countService(self, service):
        if self.services.__contains__(service):
            self.services[service] += 1
        else:
            self.services[service] = 1


class Device(object):
    def __init__(self, dev_id, rule):
        self.dev_id = dev_id
        self.rule = rule


# Para cada linea de log que haya se crea una objeto que contiene la informacion correspondiente
class Log(object):
    def __init__(self, srcip, srcport, dstip, dstport, protocol, rule_id, device, srcintf, dstintf, service):
        self.srcip = srcip
        self.srcport = srcport
        self.dstip = dstip
        self.dstport = dstport
        self.protocol = protocol
        self.rule_id = rule_id
        self.device_id = device
        self.srcintf = srcintf
        self.dstintf = dstintf
        self.service = service

    def toString(self):
        print   ("SrcIP: " + self.srcip + " | " \
                 "SrcPort: " + self.srcport + " |  " \
                 "DstIP: " + self.dstip + " | " \
                 "DstPort: " + self.dstport + " | " \
                 "Protocol: " + self.protocol + " | " \
                 "Rule ID: " + self.rule_id + " | " \
                 "Device ID: " + self.device_id)


# Este metodo muestra la informacion en pantalla.
def printResults(rulesids):
    for rule in rulesids:
        print ("\n==================================")
        print ("Rule ID: " + str(rule.id))
        print ("==================================")

        print ("---- UDP ----")
        counter = 0
        for key, value in sorted(rule.dstports_udp.items(), key=lambda k_v: (k_v[0], k_v[1]), reverse=True):
            print ("UDP: " + str(key) + " -> " + str(value))
            counter += 1
            if counter >= max_items_show:
                break

        print ("\n---- TCP ----")
        counter = 0
        for key, value in sorted(rule.dstports_tcp.items(), key=lambda k_v: (k_v[0], k_v[1]), reverse=True):
            print ("TCP: " + str(key) + " -> " + str(value))
            counter += 1
            if counter >= max_items_show:
                break

        print ("\n---- Destination IPs ----")
        counter = 0
        for key, value in sorted(rule.dstips.items(), key=lambda k_v: (k_v[0], k_v[1]), reverse=True):
            print ("Dest IP: " + str(key) + " -> " + str(value))
            counter += 1
            if counter >= max_items_show:
                break

        print ("\n---- Source IPs ----")
        counter = 0
        for key, value in sorted(rule.srcips.items(), key=lambda k_v: (k_v[0], k_v[1]), reverse=True):
            print ("Src IP: " + str(key) + " -> " + str(value))
            counter += 1
            if counter >= max_items_show:
                break

        print ("\n---- Services ----")
        counter = 0
        for key, value in sorted(rule.services.items(), key=lambda k_v: (k_v[0], k_v[1]), reverse=True):
            print ("Service: " + str(key) + " -> " + str(value))
            counter += 1
            if counter >= max_items_show:
                break


# Este metodo parsea los parametros de entrada para poder llamar a la aplicacion desde la consola
def paramParser():
    global debug, filter_action, split_character, max_items_show, file_path, output_format

    parser = argparse.ArgumentParser(description='Fortinet log parser')
    parser.add_argument('-f', '--file', required=True, help='File to be parsed', )
    parser.add_argument('-l', '--limit', type=int, default=100, help='Limit of items to show (default: 50)')
    parser.add_argument('-s', '--split', default=" ", type=str, help='Spliting character (default: " ")')
    parser.add_argument('-a', '--action', nargs='+', required=True, help='Filter action. Several action can be selected '
                                                                         'separated by spaces (accept, close, deny, ip-conn, timeout, dns)')
    parser.add_argument('-d', '--debug', default=False, help='Debug info')
    parser.add_argument('-o', '--output', choices=['csv', 'xlsx', ], default="xlsx",
                        help='Output file format (default: csv')

    args = vars(parser.parse_args())

    debug = args["debug"]
    filter_action = "|".join(args["action"])
    split_character = args["split"]
    max_items_show = args["limit"]
    file_path = args["file"]
    output_format = args["output"]


# Este metodo devuelve una cadena de texto con los keys de una diccionario por orden de recurrencia.
# Devuelve un 'No records' si no hay registros.
def buildStringFromKeys(dict):
    dict = sorted(dict.items(), key=lambda k_v: (k_v[0], k_v[1]), reverse=True)
    all_fields = ""
    counter = 0
    for key, value in dict:
        all_fields = all_fields + " " + str(key)
        counter += 1
        if counter >= max_items_show:
            return all_fields
    if all_fields == "": return "No records"
    return all_fields


# Ordena los datos de manera ascendente si se trata de numeros o por orden alfabetico si son IPs
# Esto permite ver de una manera mucho mas clara las IPs o puertos en el informe final
def sortData(data, is_number_array):
    if data == "No records":
        return data
    array = data.strip().split(" ")
    if is_number_array:
        array.sort(key=int)
        return " ".join(array)
    else:
        array.sort()
        return " ".join(array)


# Este metodo escribe en un CSV la informacion necesaria
def writingToCSV(rulesids, file):
    if not os.path.exists(reports_folder): os.makedirs(reports_folder)
    file = open(file, "wb")
    file.write("Rule ID,Source IPs,Destination IPs,TCP ports,UDP ports\n")
    for rule in rulesids:
        line = str(rule.id)+", " + \
               sortData(buildStringFromKeys(rule.srcips, False)) + ", " + \
               sortData(buildStringFromKeys(rule.dstips, False)) + ", " + \
               sortData(buildStringFromKeys(rule.dstports_tcp, False)) + ", " + \
               sortData(buildStringFromKeys(rule.dstports_udp, False)) + ",\n"
        file.write(line)


# Este metodo escribe en un XLSX la informacion extraida de los logs
def writingToXLSX(rulesids, file):
    if not os.path.exists(reports_folder): os.makedirs(reports_folder)
    workbook = xlsxwriter.Workbook(file)
    worksheet = workbook.add_worksheet()

    filter_format = workbook.add_format({'bold': True, 'font_color': 'orange', 'font_size': 20, 'valign':'top', 'align':'left'})
    bold = workbook.add_format({'bold': True, 'valign':'top', 'align':'left'})
    normal = workbook.add_format({'text_wrap': True, 'center_across': True, 'valign':'top', 'align':'left'})

    # Setea la altura de la fila 1 a 48
    worksheet.set_row(0, 37)
    worksheet.set_column(0,8, 14)

    # worksheet.insert_image('A1', 'resources/logo.png')
    worksheet.write('B1', "Applied filter: " + filter_action, filter_format)
    worksheet.write('A2','Rule ID',bold)
    worksheet.write('B2','Src IP',bold)
    worksheet.write('C2','Dst IP',bold)
    worksheet.write('D2','TCP Port',bold)
    worksheet.write('E2','UDP Port',bold)
    worksheet.write('F2', 'Services', bold)
    worksheet.write('G2', 'Src Interface', bold)
    worksheet.write('H2', 'Dst Interface', bold)

    row = 3

    for rule in rulesids:
        worksheet.write("A" + str(row), str(rule.id).strip(), bold)
        worksheet.write("B" + str(row), sortData(buildStringFromKeys(rule.srcips), False), normal)
        worksheet.write("C" + str(row), sortData(buildStringFromKeys(rule.dstips), False), normal)
        worksheet.write("D" + str(row), sortData(buildStringFromKeys(rule.dstports_tcp), True), normal)
        worksheet.write("E" + str(row), sortData(buildStringFromKeys(rule.dstports_udp), False), normal)
        worksheet.write("F" + str(row), sortData(buildStringFromKeys(rule.services), False), normal)
        worksheet.write("G" + str(row), sortData(buildStringFromKeys(rule.srcintf), False), normal)
        worksheet.write("H" + str(row), sortData(buildStringFromKeys(rule.dstintf), False), normal)
        row += 1

    workbook.close()


# Este metodo devuelve los campos a analizar de cada log en forma de array o None si no es interesante para su estudio
def getFields(fields):
    try:
        srcip, srcport, dstip, dstport, proto, policyid, action, devid,srcintf,dstintf,service = "","","","","","","","","","",""
        for field in fields:
            if field.startswith("srcip="):
                srcip = field.split("=")[1]
            elif field.startswith("srcport="):
                srcport = field.split("=")[1]
            elif field.startswith("dstip="):
                dstip = field.split("=")[1]
            elif field.startswith("dstport="):
                dstport = field.split("=")[1]
            elif field.startswith("proto="):
                proto = field.split("=")[1]
            elif field.startswith("policyid="):
                policyid = field.split("=")[1]
            elif field.startswith("action="):
                action = field.split("=")[1]
            elif field.startswith("devname="):
                devid = field.split("=")[1]
            elif field.startswith("srcintf="):
                srcintf = field.split("=")[1]
            elif field.startswith("dstintf="):
                dstintf = field.split("=")[1]
            elif field.startswith("service="):
                service = field.split("=")[1]

        if not re.search(filter_action, action):
        #if action != filter_action:
            return None

        return srcip, srcport, dstip, dstport, proto, policyid, action, devid, srcintf, dstintf, service
    except:
        if debug: "[ERROR] Error while parsing line -> " + fields
        return None


# Este metodo parsea los datos del logs por campo. Esto es tan facil como cambiar este metodo para otros firewalls
# de los que se desee analizar la informacion mediante logs.
def parseFile(filepath):
    logs = []
    counter = 0

    try:
        with open(filepath) as file:
            lines = file.readlines()
            for line in lines:
                counter += 1

                sys.stdout.write("[INFO] " + str(counter) + "/" + str(len(lines)) + " read lines...   \r")
                sys.stdout.flush()

                line = line.replace('"', '')
                all_fields = line.split(split_character)
                fields = getFields(all_fields)

                if debug: print (fields)

                try:
                    if fields != None:
                        log = Log(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[7], fields[8], fields[9], fields[10])
                        if debug: log.toString()
                        logs.append(log)
                except IndexError as e:
                    if debug: print ("[DEBUG] " + str(e))
                    if "app=PING" in line:
                        if debug: print ("[DEBUG] Ping packet detected... discarded")
                    else:
                        if debug: print ("[DEBUG] Line not read -> " + line)
        return logs
    except IOError:
        print ("[ERROR] File <" + file_path + "> not found...")
        sys.exit(2)


# Aqui se contabilizan los datos de cada regla en tuplas. De este modo, cada regla tencra asociada varias tuplas
# donde se contaran el numero de accesos de cada ip origen, ip destino, puerto de destino y puerto de origen.
def countValues(logs):
    rulesids = []
    found = False
    for log in logs:
        found = False
        for rule in rulesids:
            if log.rule_id == str(rule.id):
                found = True
                rule.countPort(log.dstport, log.protocol)
                rule.countDstIP(log.dstip)
                rule.countSrcIP(log.srcip)
                rule.countSrcIntf(log.srcintf)
                rule.countDstIntf(log.dstintf)
                rule.countService(log.service)
                break

        if found == False:
            new_rule = RuleID(log.rule_id, log.dstport, log.protocol, log.dstip, log.srcip, log.srcintf, log.dstintf, log.service)
            rulesids.append(new_rule)
    return rulesids


def main():
    paramParser()
    print (banner)
    print ("[INFO] Loading files. Please wait...")
    logs = parseFile(file_path)
    print ("[INFO] File parsed. Sorting the info...")
    rulesids = countValues(logs)
    rulesids = sorted(rulesids, key=lambda x: x.id)
    printResults(rulesids)
    print ("=======================================")
    print ("[INFO] " + str(len(rulesids)) + " rules analyzed...")
    if output_format == "xlsx":
        file = reports_folder + "/" + file_path + "_" + xslx_filename
        writingToXLSX(rulesids, file)
        print ("[INFO] XLSX report created at '" + os.path.abspath(file) + "'")
    if output_format == "csv":
        file = reports_folder + "/"  + file_path + "_"+ csv_filename
        writingToCSV(rulesids, file)
        print ("[INFO] CSV report created at '" + os.path.abspath(file) + "'")


if __name__ == "__main__":
    main()
