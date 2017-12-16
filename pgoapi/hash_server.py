from __future__ import absolute_import

import ctypes
import base64
import requests
import logging

from struct import pack, unpack
from collections import namedtuple

from pgoapi.exceptions import BadHashRequestException, HashingOfflineException, HashingQuotaExceededException, HashingTimeoutException, MalformedHashResponseException, NoHashKeyException, TempHashingBanException, UnexpectedHashResponseException

HashResult = namedtuple('HashResult', 'location_auth_hash location_hash request_hashes status')

class HashServer:
    _log = log = logging.getLogger(__name__)
    _session = requests.session()
    _adapter = requests.adapters.HTTPAdapter(pool_maxsize=150, pool_block=True)
    _session.mount('https://', _adapter)
    _session.mount('http://', _adapter)
    _session.verify = True
    _session.headers.update({'User-Agent': 'Python pgoapi @pogodev'})
    _endpoint = "http://hash.goman.io/api/v153_2/hash"
    # _endpoint = "https://pokehash.buddyauth.com/api/v153_2/hash"
    _headers = {'content-type': 'application/json', 'Accept': 'application/json'}

    @staticmethod
    def hash(timestamp, latitude, longitude, accuracy, authticket, sessiondata, requestslist, token):
        if not token:
            raise NoHashKeyException('Token not provided for hashing server.')
        payload = {
            'Timestamp': timestamp,
            'Latitude64': unpack('<q', pack('<d', latitude))[0],
            'Longitude64': unpack('<q', pack('<d', longitude))[0],
            'Accuracy64': unpack('<q', pack('<d', accuracy))[0],
            'AuthTicket': base64.b64encode(authticket).decode('ascii'),
            'SessionData': base64.b64encode(sessiondata).decode('ascii'),
            'Requests': [base64.b64encode(x.SerializeToString()).decode('ascii') for x in requestslist]
        }
        headers = HashServer._headers.copy()
        headers['X-AuthToken'] = token
        # request hashes from hashing server
        try:
            response = HashServer._session.post(HashServer._endpoint, json=payload, headers=headers, timeout=30)
        except requests.exceptions.Timeout:
            raise HashingTimeoutException('Hashing request timed out.')
        except requests.exceptions.ConnectionError as error:
            raise HashingOfflineException(error)

        if response.status_code == 400:
            raise BadHashRequestException("400: Bad request, error: {}".format(response.text))
        elif response.status_code == 403:
            raise TempHashingBanException('Your IP was temporarily banned for sending too many requests with invalid keys')
        elif response.status_code == 429:
            raise HashingQuotaExceededException("429: Request limited, error: {}".format(response.text))
        elif response.status_code in (502, 503, 504):
            raise HashingOfflineException('{} Server Error'.format(response.status_code))
        elif response.status_code != 200:
            error = 'Unexpected HTTP server response - needs 200 got {c}. {t}'.format(
                c=response.status_code, t=response.text)
            raise UnexpectedHashResponseException(error)

        if not response.content:
            raise MalformedHashResponseException('Response was empty')

        try:
            response_parsed = response.json()
            HashServer.log.debug(response_parsed)
        except ValueError:
            raise MalformedHashResponseException('Unable to parse JSON from hash server.')

        headers = response.headers
        status = {}
        try:
            status['period'] = int(headers.get('X-RatePeriodEnd', 0))
            status['remaining'] = int(headers('X-RateRequestsRemaining', 0))
            status['maximum'] = int(headers('X-MaxRequestCount', 0))
            status['expiration'] = int(headers('X-AuthTokenExpiration', 0))
            status['token'] = token
        except (KeyError, TypeError, ValueError):
            pass

        request_hashes = []
        for request_hash in response_parsed['requestHashes']:
            request_hashes.append(ctypes.c_uint64(request_hash).value)

        result = HashResult(
            location_auth_hash=ctypes.c_int32(response_parsed['locationAuthHash']).value,
            location_hash=ctypes.c_int32(response_parsed['locationHash']).value,
            request_hashes=request_hashes,
            status=status)
        HashServer.log.debug(result)
        return result
