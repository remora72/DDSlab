import xml.etree.ElementTree as ET

# Archivo XML de entrada
input_file = "/home/ubuntu/work/dds/repositories/DDSlab/data/qualys/latest.qkdb.xml"

# Archivo XML de salida
output_file = "/home/ubuntu/work/dds/repositories/DDSlab/data/qualys/latest.qkdb_out.xml"


# Parsear el archivo de entrada como un árbol de elementos
tree = ET.parse(input_file)
root = tree.getroot()

# Buscar todos los elementos VULN en el árbol
vuln_elems = root.findall(".//VULN")

# Iterar sobre cada elemento VULN y agregar el elemento CVE_LIST
for vuln_elem in vuln_elems:

    # Si el elemento CVE_LIST no existe, agregarlo
    if vuln_elem.find("CVE_LIST") is None:
        cve_list_elem = ET.SubElement(vuln_elem, "CVE_LIST")
        cve_elem = ET.SubElement(cve_list_elem, "CVE")
        id_elem = ET.SubElement(cve_elem, "ID")
    else:
        # Si el elemento CVE_LIST existe, buscar todos los elementos CVE
        cve_elems = vuln_elem.findall(".//CVE")
        # Iterar sobre cada elemento CVE y borrar el elemento URL si existe
        for cve_elem in cve_elems:
            url_elem = cve_elem.find("URL")
            if url_elem is not None:
                cve_elem.remove(url_elem)

    # Si el elemento BUGTRAQ_LIST no existe, agregarlo
    if vuln_elem.find("BUGTRAQ_LIST") is None:
        bt_list_elem = ET.SubElement(vuln_elem, "BUGTRAQ_LIST")
        bt_elem = ET.SubElement(bt_list_elem, "BUGTRAQ")
        id_elem = ET.SubElement(bt_elem, "ID")
    else:
        # Si el elemento BUGTRAQ_LIST existe, buscar todos los elementos BUGTRAQ
        bt_elems = vuln_elem.findall(".//BUGTRAQ")
        # Iterar sobre cada elemento BUGTRAQ y borrar el elemento URL si existe
        for bt_elem in bt_elems:
            url_elem = bt_elem.find("URL")
            if url_elem is not None:
                bt_elem.remove(url_elem)

            # Buscamos los ID y les poner el prefijo "BT-"
            id_elem = bt_elem.find("ID")
            if id_elem is not None:
                id_value = id_elem.text
            try:
                id_value = int(id_value)
                new_id_value = "BT-" + str(id_value)
                id_elem.text = new_id_value
            except ValueError:
                pass


# Escribir el árbol de elementos modificado en el archivo de salida
tree.write(output_file)

