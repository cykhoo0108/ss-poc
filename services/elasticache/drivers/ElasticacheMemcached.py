from .ElasticacheCommon import ElasticacheCommon


class ElasticacheMemcached(ElasticacheCommon):
    def __init__(self, cluster, client, driver_info):
        super().__init__(cluster, client, driver_info)
        # self.init()

    def _checkDefaultPort(self):
        # Memcached returns ConfigurationEndpoint with port information
        # self.cluster.get('ConfigurationEndpoint').get('Port')
        # self.cluster.get('CacheNodes')[0].get('Endpoint').get('Port')
        if self.cluster.get('ConfigurationEndpoint').get('Port') == 11211:
            self.results['DefaultPort'] = [-1,
                                           f"Using default Memcached port 11211"]

