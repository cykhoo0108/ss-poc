from .ElasticacheCommon import ElasticacheCommon


class ElasticacheRedis(ElasticacheCommon):
    def __init__(self, cluster, client, driver_info):
        super().__init__(cluster, client, driver_info)
        # self.init()

    def _checkDefaultPort(self):
        ports_in_cluster = [node.get('Endpoint').get(
            'Port') for node in self.cluster.get('CacheNodes')]
        if any(port == 6379 for port in ports_in_cluster):
            self.results['DefaultPort'] = [-1,
                                           f"Using default Redis port 6379"]