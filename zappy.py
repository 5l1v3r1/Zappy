import time
from zapv2 import ZAPv2


class ScanPluginObject:
    def __init__(self, attack_name, unknown, status, progress, time_elapsed, requests, alerts):
        self.attack_name = attack_name
        self.unknown = unknown
        self.status = status
        self.progress = progress
        self.time_elapsed = time_elapsed
        self.requests = requests
        self.alerts = alerts


class ScanAlert:
    def __init__(self, sourceid, other, method, evidence, pluginId, cweid, confidence, wascid, description,
                 messageId, url, reference, solution, alert, param, attack, name, risk, id):
        self.sourceid = int(sourceid) if sourceid != "" else None
        self.other = other
        self.method = method
        self.evidence = evidence
        self.plugin_id = int(pluginId) if pluginId != "" else None
        self.cweid = cweid
        self.confidence = confidence
        self.wascid = int(wascid) if wascid != "" else None
        self.description = description
        self.message_id = int(messageId) if messageId != "" else None
        self.url = url
        self.reference = reference
        self.solution = solution
        self.alert = alert
        self.param = param
        self.attack = attack
        self.name = name
        self.risk = risk
        self.id = int(id)


class Scan:
    def __init__(self, target, api_key: str = None, host: str = "localhost", port: int = 8080):

        self.target = target[:-1] if target.endswith("/") else target  # The URL of the application to be tested (and delete "/" at end)
        self._zap = ZAPv2(apikey=api_key, proxies={'http': f'http://{host}:{port}', 'https': f'http://{host}:{port}'})  # Connect to API endpoint
        self.urls = []

    class Crawler:
        def __init__(self, zap: ZAPv2, target: str):
            self.zap = zap
            self.scan_id = zap.spider.scan(target)

        def progress(self) -> int:
            return int(self.zap.spider.status(self.scan_id))

        def results(self):
            return list(map(str, self.zap.spider.results(self.scan_id)))

    def start_crawler(self) -> Crawler:
        return self.Crawler(self._zap, self.target)

    class Attack:
        def __init__(self, zap: ZAPv2, target: str):
            self.zap = zap
            self.target = target
            self.scan_id = zap.ascan.scan(target)

        def progress(self) -> int:
            return int(self.zap.ascan.status(self.scan_id))

        def results(self):
            return [ScanAlert(**x) for x in self.zap.alert.alerts(baseurl=self.target)]

    def start_attack(self) -> Attack:
        return self.Attack(self._zap, self.target)

    def run_full_scan(self):
        scan_id = self._zap.ascan.scan(self.target)
        while int(self._zap.ascan.status(scan_id)) < 100:
            # Loop until the scanner has finished
            print('Scan progress %: {}'.format(self._zap.ascan.status(scan_id)))

            scan = self._zap.ascan.scan_progress(scan_id)  # get all (saved and active) self._zap scans

            for i in range(len(scan)):  # search for scan on this self.target
                if scan[i] == self.target:  # if self.target found
                    scan_progress = scan[i + 1]
                    scan_attacks = [ScanPluginObject(*scan["Plugin"]) for scan in scan_progress["HostProcess"]]
                    time.sleep(5)
                    break
            else:  # if self.target not found in scan list
                raise Exception("Scan not found in self._zap scan list.")

        alerts = self._zap.alert.alerts(baseurl=self.target)

        informational = [alert for alert in alerts if alert["risk"] == "Informational"]
        low = [alert for alert in alerts if alert["risk"] == "Low"]
        medium = [alert for alert in alerts if alert["risk"] == "Medium"]
        high = [alert for alert in alerts if alert["risk"] == "High"]

        print(f"""
        Informational: {len(informational)}
        Low          : {len(low)}
        Medium       : {len(medium)}
        High         : {len(high)}
        """
              )


if __name__ == '__main__':
    scan = Scan(target=input("target URL: "))

    crawler = scan.start_crawler()
    print("started crawler.")
    while crawler.progress() < 100:
        print(crawler.progress())
    print(crawler.results())

    attack = scan.start_attack()
    while attack.progress() < 100:
        print(attack.progress())
    alerts = attack.results()

    informational = [alert for alert in alerts if alert.risk == "Informational"]
    low = [alert for alert in alerts if alert.risk == "Low"]
    medium = [alert for alert in alerts if alert.risk == "Medium"]
    high = [alert for alert in alerts if alert.risk == "High"]

    print("High risk alerts:")
    [print(alert, "\n") for alert in high]
