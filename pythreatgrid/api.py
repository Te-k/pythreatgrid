import requests
import os
from datetime import datetime, timedelta


class ThreatGridError(Exception):
    def __init__(self, message):
        self.message = message
        Exception.__init__(self, message)


class ThreatGrid(object):
    def __init__(self, key):
        self.key = key
        self.base_url = "https://panacea.threatgrid.com/api/v2/"
        self.search_types = ['regkey', 'path', 'ip', 'domains', 'artifacts', 'url']
        self.sample_search_types = ['checksum', 'checksum_sample', 'path', 'path_sample', 'path_artifact', 'path_deleted', 'url', 'registry_key', 'domain', 'domain_dns_lookup', 'domain_http_request', 'ip', 'ip_dns_lookup', 'ip_src', 'ip_dst', 'ioc', 'tag']
        self.sample_types = ['sha256', 'md5', 'sha1', 'id', 'ioc', 'submission_id', 'submission_ids']
        # TODO: user agent

    def _request(self, path, params):
        params['api_key'] = self.key
        r = requests.get(self.base_url + path, params=params)
        if r.status_code != 200:
            raise ThreatGridError('Bad HTTP Status Code %i' % r.status_code)
        return r.json()

    def search_submissions(self, query, limit=None, before=None, after=None):
        """
        Search in Threat Grid Submissions

        Parameters
        -----------
        query: string
            Query
        limit: int
            Limit the number of results (optional)
        before: datetime
            Limit research to samples submitted before that day
        after: datetime
            Limit research to samples submitted after that day

        Returns
        -------
        dict
            Dictionary of results
        """
        params = {'q': query}
        if limit:
            params['limit'] = limit
        if before:
            params['before'] = before.strftime('%Y-%m-%%d')
        if after:
            params['after'] = after.strftime('%Y-%m-%%d')
        return self._request('search/submissions', params)['data']

    def search_samples(self, query, type='md5', before=None, after=None, org_only=False, user_only=False, limit=None):
        """
        Search for samples in Threat Grid data

        Parameters
        ----------
        query: str
            Value of the query
        type: str
            Type from the following list : 'checksum', 'checksum_sample', 'path', 'path_sample', 'path_artifact', 'path_deleted', 'url', 'registry_key', 'domain', 'domain_dns_lookup', 'domain_http_request', 'ip', 'ip_dns_lookup', 'ip_src', 'ip_dst', 'ioc', 'tag'
        before: datetime
            Late limit in sample submission (optional)
        after: datetime
            Early limit in sample submission (optional)
        org_only: boolean
            Searches only in the organisation samples (default: False)
        user_only: boolean
            Searches only in the user samples

        Returns
        -------
        dict
            Data about the samples
        """
        if type not in self.sample_search_types:
            raise ThreatGridError('Invalid Sample Type')
        params = {type: query, 'org_only': org_only, 'user_only': user_only}
        if limit:
            params['limit'] = limit
        if before:
            params['before'] = before.strftime('%Y-%m-%%d')
        if after:
            params['after'] = after.strftime('%Y-%m-%%d')
        return self._request('samples/search', params)['data']


    def get_analysis(self, sample_id):
        return self._request('sample/%i/analysis.json' % sample_id, {})

    def get_sample(self, query, type='md5', before=None, after=None, org_only=False, user_only=False):
        """
        Get information on a given sample

        Parameters
        ----------
        query: str
            Query string
        type: str
            Type of query (accepted values: 'sha256', 'md5', 'sha1', 'id', 'ioc', 'submission_id', 'submission_ids')
        before: datetime
            Search for samples before this date (optional, default is today)
        after: datetime
            Search for samples after this date (default is today-1year)
        org_only: boolean
            Searches only in the organisation samples (default: False)
        user_only: boolean
            Searches only in the user samples

        Returns
        -------
        dict

        """
        if type not in self.sample_types:
            raise ThreatGridError('Invalid Sample Type')
        if before is None:
            before = datetime.now().strftime('%Y-%m-%d')
        if after is None:
            after = (datetime.now() - timedelta(days=365)).strftime('%Y-%m-%d')
        params = {type: query, 'org_only': org_only, 'user_only': user_only, 'before': before, 'after': after}
        return self._request('samples', params)['data']

    def submit(self):
        raise NotImplemented()
