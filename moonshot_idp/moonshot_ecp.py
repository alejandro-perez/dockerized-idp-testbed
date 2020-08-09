#! /usr/bin/env python3
#
# SAML ECP user authentication and SAML Assertion retrieval example
# Alejandro Perez-Mendez (alex.perez-mendez@jisc.ac.uk)
#
import radiusd
import requests
import datetime
import xml.etree.ElementTree as ET

# The ECP entrypoint of your IDP
URL = 'https://idp:4443/idp/profile/SAML2/SOAP/ECP'

# The AssertionConsumerServiceUrl of the requesting SP
ASSERTION_CONSUMER_SERVICE_URL='https://idptestbed/Shibboleth.sso/SAML2/ECP'

# The EntityID of the requesting SP
REMOTE_ENTITY_ID = 'https://sp.idptestbed/shibboleth'


def get_radius_attribute(p, attribute_name):
    """ Utility function to get an attribute from a tuple
    """
    try:
        return next(value for name, value in p if name == attribute_name)
    except StopIteration:
        return None


def assertion_to_attribute_tuples(assertion):
    """ Utility function to convert an assertion string into a list of attribute tuples of type SAML-AAA-Assertion
    """
    max_rad_attr_len = 220
    return tuple(('SAML-AAA-Assertion', '+=', assertion[i:i + max_rad_attr_len])
                 for i in range(0, len(assertion), max_rad_attr_len))


def authenticate(p):
    """ The authenticate() method
    """
    radiusd.radlog(radiusd.L_INFO, 'Trying to authenticate user using ECP')
    username = get_radius_attribute(p['request'], 'User-Name')
    passwd = get_radius_attribute(p['request'], 'User-Password')
    if not (username and passwd):
        radiusd.radlog(radiusd.L_ERR, 'Could not find User-Name and User-Password attributes. Are you using PAP?')
        return radiusd.RLM_MODULE_FAIL
    assertion = do_ecp(username, passwd)
    if assertion is None:
        radiusd.radlog(radiusd.L_ERR, 'The IDP rejected the user authentication')
        return radiusd.RLM_MODULE_FAIL

    update_dict = {"reply": assertion_to_attribute_tuples(assertion)}
    return radiusd.RLM_MODULE_OK, update_dict


def do_ecp(username, password):
    """ Sends the ECP request and parses the response
    """
    now = datetime.datetime.utcnow().isoformat()
    request= f'''
    <SOAP-ENV:Envelope
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
      xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp">
      <SOAP-ENV:Header>
      </SOAP-ENV:Header>
      <SOAP-ENV:Body>
          <samlp:AuthnRequest
                  ID="ID-{now}"
                  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS"
                  AssertionConsumerServiceURL="{ASSERTION_CONSUMER_SERVICE_URL}"
                  IssueInstant="{now}"
                  Version="2.0">
              <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                  {REMOTE_ENTITY_ID}
              </saml:Issuer>
              <samlp:NameIDPolicy AllowCreate="1"/>
          </samlp:AuthnRequest>
       </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>'''

    try:
        # Send the ECP request (SSL disabled for simplicity)
        r = requests.post(URL, auth=(username, password), data=request, headers={'content-type': 'text/xml'}, verify=False)
        # Parses the XML response
        tree = ET.fromstring(r.text)
        # check if authentication failed
        auth_ok = tree.findall(".//{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode[@Value='urn:oasis:names:tc:SAML:2.0:status:Success']")
        if not auth_ok:
            radiusd.radlog(radiusd.L_DBG, 'IDP rejected the user')
            return None
        # Get Assertion
        assertion = tree.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        return ET.tostring(assertion).decode()
    except requests.exceptions.RequestException as ex:
        radiusd.radlog(radiusd.L_DBG, 'An exception happened when talking to the IDP: {}'.format(ex))
        return None
