import boto3
import logging

from ScoutSuite import __version__
from ScoutSuite.providers.aws.utils import get_caller_identity
from ScoutSuite.providers.base.authentication_strategy import AuthenticationStrategy, AuthenticationException
from botocore.credentials import RefreshableCredentials
from dateutil.parser import parse
from botocore.session import get_session
from credrefresh import CredRefresher
from initial_creds import init_keys

class AWSCredentials:

    def __init__(self, session):
        self.session = session


class AWSAuthenticationStrategy(AuthenticationStrategy):
    """
    Implements authentication for the AWS provider
    """

    def authenticate(self,
                     profile=None,
                     aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None,
                     **kwargs):

        try:

            # Set logging level to error for libraries as otherwise generates a lot of warnings
            logging.getLogger('botocore').setLevel(logging.ERROR)
            logging.getLogger('botocore.auth').setLevel(logging.ERROR)
            logging.getLogger('urllib3').setLevel(logging.ERROR)

            refreshable_creds = RefreshableCredentials(
                access_key=init_keys.get('access_key'),
                secret_key=init_keys.get('secret_key'),
                token=init_keys.get('token'),
                expiry_time=parse(init_keys.get('expiry_time')),
                refresh_using=CredRefresher.refresh_creds,
                method="custom-jwt",
            )
            refreshable_session = get_session()
            refreshable_session._credentials = refreshable_creds
            session = boto3.Session(botocore_session=refreshable_session)

            # Test querying for current user
            get_caller_identity(session)

            # Set custom user agent
            session._session.user_agent_name = 'Scout Suite'
            session._session.user_agent_extra = 'Scout Suite/{} (https://github.com/nccgroup/ScoutSuite)'.format(__version__)
            session._session.user_agent_version = __version__

            return AWSCredentials(session=session)

        except Exception as e:
            raise AuthenticationException(e)
