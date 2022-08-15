import json

import requests
from requests import RequestException

from elastalert.alerts import Alerter, BasicMatchString, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger


class NiketechServiceNowAlerter(Alerter):
    """ Creates a Niketech ServiceNow alert """
    required_options = set([
        'access_key',
        'assignment_group',
        'client_id',
        'client_secret',
        'impacted_geo',
        'requested_by',
        'requested_for',
        'requested_for_location',
        'service'
    ])

    def __init__(self, rule):
        super(NiketechServiceNowAlerter, self).__init__(rule)

        self.category = self.rule.get('category', None)
        self.contact_type = self.rule.get('contact_type', 'Integration')
        self.impact = self.rule.get('servicenow_impact', '3')
        self.servicenow_api_root = self.rule.get('servicenow_api_root', '/api/nike2')
        self.servicenow_server_url = self.rule.get('servicenow_server_url', 'https://niketech.service-now.com')
        self.servicenow_proxy = self.rule.get('servicenow_proxy', None)
        self.subcategory = self.rule.get('subcategory', None)
        self.urgency = self.rule.get('servicenow_urgency', '3')

    def alert(self, matches):
        # Set proper headers
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json;charset=utf-8"
        }

        # Request authorization token
        auth_payload = {
            "client_id": self.rule['client_id'],
            "client_secret": self.rule['client_secret']
        }
        service_now_api_url = self.servicenow_server_url + self.servicenow_api_root
        try:
            response = requests.post(
                service_now_api_url + '/application_credentials/generate_refresh_token',
                data=json.dumps(auth_payload)
            )
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to ServiceNow: %s" % e)
        result = response.json().get('result')
        if not type(result) is dict:
            raise EAException("Wrong authentication result from ServiceNow: %s" % result)
        try:
            access_token = result['Access Token']
        except KeyError:
            raise EAException("ServiceNow didn't return Access Token: %s" % result)

        headers["Authorization"] = "Bearer " + access_token
        short_description = self.rule.get('short_description', self.create_title(matches))
        for match in matches:
            # Parse everything into description.
            detailed_description = str(BasicMatchString(self.rule, match))

        payload = {
            "access_key": self.rule['access_key'],
            "assignment_group": self.rule['assignment_group'],
            "contact_type": self.contact_type,
            "detailed_description": detailed_description,
            "impact": self.impact,
            "impacted_geo": self.rule['impacted_geo'],
            "requested_by": self.rule['requested_by'],
            "requested_for": self.rule['requested_for'],
            "requested_for_location": self.rule['requested_for_location'],
            "service": self.rule['service'],
            "short_description": short_description,
            "urgency": self.urgency
        }
        if self.category != None:
            payload["category"] = self.category
        if self.subcategory != None:
            payload["subcategory"] = self.subcategory
        if self.service_area != None:
            payload["service_area"] = self.service_area
        try:
            response = requests.post(
                service_now_api_url + '/incident_service_api/create_incident',
                headers=headers,
                data=json.dumps(payload, cls=DateTimeEncoder)
            )
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to ServiceNow: %s" % e)
        elastalert_logger.info("Alert sent to ServiceNow")

    def get_info(self):
        return {'type': 'NiketechServiceNow',
                'self.servicenow_server_url': self.servicenow_server_url}
