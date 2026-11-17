import asyncio
import xml.etree.ElementTree as ET
from typing import Dict, Any, List

PROFILE_ARGS = {
    "safe": ["-sT", "-T3", "--top-ports", "100"],
    "standard": ["-sV", "-T4", "--top-ports", "1000"],
    "aggressive": ["-sV", "-sC", "-O", "-T4", "-p-"],
}

async def run_nmap_scan(target_host: str, profile: str = "standard") -> Dict[str, Any]:
    args = PROFILE_ARGS.get(profile, PROFILE_ARGS["standard"])
    cmd = ["nmap", *args, "-oX", "-", target_host]

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600)
    except asyncio.TimeoutError:
        process.kill()
        raise RuntimeError(f"Nmap scan timed out for target {target_host}")

    if process.returncode != 0:
        err_msg = stderr.decode("utf-8", errors="ignore").strip()
        raise RuntimeError(f"Nmap failed (code {process.returncode}): {err_msg}")

    xml_output = stdout.decode("utf-8", errors="ignore")
    return parse_nmap_xml(xml_output)

def parse_nmap_xml(xml_data: str) -> Dict[str, Any]:
    root = ET.fromstring(xml_data)
    results: List[Dict[str, Any]] = []
    os_matches: List[str] = []

    for host in root.findall("host"):
        # Parse OS detection if present
        os_el = host.find("os")
        if os_el is not None:
            for osmatch in os_el.findall("osmatch"):
                name = osmatch.attrib.get("name")
                acc = osmatch.attrib.get("accuracy")
                if name:
                    os_matches.append(f"{name} ({acc}%)")

        # Parse open ports and service banners
        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue

            port_num = int(port_el.attrib.get("portid", 0))
            protocol = port_el.attrib.get("protocol", "tcp")

            service_el = port_el.find("service")
            service_name = service_el.attrib.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.attrib.get("product", "") if service_el is not None else ""
            version = service_el.attrib.get("version", "") if service_el is not None else ""
            banner = " ".join(filter(None, [product, version])).strip()

            results.append({
                "port": port_num,
                "protocol": protocol,
                "service": service_name,
                "banner": banner,
                "state": "open",
            })

    return {
        "open_ports_count": len(results),
        "os_guesses": os_matches[:3],
        "ports": results,
    }