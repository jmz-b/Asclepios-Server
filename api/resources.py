from tastypie.resources import ModelResource, Resource, fields
from api.models import CipherText, Map
from tastypie.authorization import Authorization
from tastypie.bundle import Bundle
from tastypie.exceptions import NotFound
import requests
import json
import hashlib
# import the logging library
import logging
import os

#===============================================================================
# Common functions
#===============================================================================  
def hash(input):
    h = hashlib.sha256(input).hexdigest()
    return h


# Get an instance of a logger
logger = logging.getLogger(__name__)

# Get URL of Trusted Authority (TA)
URL_TA = os.environ['TA_SERVER']#"http://127.0.0.1:8000/api/v1/search/"#"http://127.0.0.1:8000/api/v1/search/" #os.getenv('TA_SERVER')
    
#===============================================================================
# "Ciphertext" resource
#===============================================================================   
class CiphertextResource(ModelResource):

    class Meta:
        queryset = CipherText.objects.all()
        resource_name = 'ciphertext'
        authorization = Authorization()
        filtering = {
            "jsonId": ['exact'],
        }

    
#===============================================================================
# "Map" resource
#===============================================================================   
class MapResource(ModelResource):

    class Meta:
        queryset = Map.objects.all()
        resource_name = 'map'
        authorization = Authorization()
        filtering = {
            "address": ['exact'],
        }

    
#===============================================================================
# "Search Query" object
#===============================================================================       
class Search(object):
    KeyW = ''
    fileno = 0
    Lu = []
    Cfw = []

    
#===============================================================================
# "Search Query" resource
#===============================================================================   
class SearchResource(Resource):
    KeyW = fields.CharField(attribute='KeyW')
    fileno = fields.IntegerField(attribute='fileno')
    Lu = fields.ListField(attribute='Lu')
    Cfw = fields.ListField(attribute="Cfw")
    
    class Meta:
        resource_name = 'search'
        object_class = Search
        authorization = Authorization()
        always_return_data=True

    # adapted this from ModelResource
    def get_resource_uri(self, bundle_or_obj):
        kwargs = {
            'resource_name': self._meta.resource_name,
        }

        if isinstance(bundle_or_obj, Bundle):
            kwargs['pk'] = bundle_or_obj.obj.KeyW  # pk is referenced in ModelResource
        else:
            kwargs['pk'] = bundle_or_obj.KeyW
        
        if self._meta.api_name is not None:
            kwargs['api_name'] = self._meta.api_name
        
        return self._build_reverse_url('api_dispatch_detail', kwargs=kwargs)

    def get_object_list(self, request):
        # inner get of object list... this is where you'll need to
        # fetch the data from what ever data source
        return 0

    def obj_get_list(self, request=None, **kwargs):
        # outer get of object list... this calls get_object_list and
        # could be a point at which additional filtering may be applied
        return self.get_object_list(request)

    def obj_get(self, request=None, **kwargs):
        # get one object from data source
        data = {"KeyW":self.KeyW, "fileno":self.fileno, "Lu":self.Lu, "Cfw":self.Cfw}
        return data
    
    def obj_create(self, bundle, request=None, **kwargs):
        logger.info("Search in SSE Server")
        logger.debug("TA url: %s",URL_TA)
        
        # create a new object
        bundle.obj = Search()
         
        # full_hydrate does the heavy lifting mapping the
        # POST-ed payload key/values to object attribute/values
        bundle = self.full_hydrate(bundle)
         
        logger.debug("Received data from user %s:", " - KeyW: ",bundle.obj.KeyW, " - file number: ", bundle.obj.fileno, " - Lu:", bundle.obj.Lu)
        
        # invoke API of TA
        fileno = bundle.obj.fileno
        KeyW = json.dumps(bundle.obj.KeyW)
        
        logger.debug("KeyW: %s", KeyW)
        
        data = {}
        data["KeyW"] = bundle.obj.KeyW
        data["fileno"] = bundle.obj.fileno
        
        logger.debug("json data: %s", data)
        logger.debug("URL_TA: %s",URL_TA)
        
        # Send request to TA
        logger.debug("Send request to TA")
        response = requests.post(URL_TA, json=data)  
        
        logger.debug("Response from TA: Lta = %s", response.text)
        
        # compare the list received from TA with the list received from the user
        Lu = bundle.obj.Lu
        logger.debug("List from user: %s", Lu)
        Lta = response.json()["Lta"]
        logger.debug("List from TA: %s", Lta)
        
        if Lu == Lta:
            logger.debug("Lu = Lta")
            # Identify list of json identifiers
            #Cfw = []
            
            # List of encrypted data
            CipherL = []

            logger.debug("fileno: %s",fileno)  
            for i in range(1, int(fileno) + 1): # fileno starts at 1
                logger.debug("i: %s", i)
                KeyW_ciphertext = json.loads(KeyW)['ct'] # get value of json
                input =  (KeyW_ciphertext + str(i) + "0").encode('utf-8')
                addr = hash(input)
                logger.debug("hash input to compute address: %s", input)
                logger.debug("the hash output (computed from KeyW): %s", addr)
                logger.debug("type of addr: %s",type(addr))

                try:
                    logger.debug("finding address")
                    
                    # Retrieve value which corresponds to the address 'addr'
                    cf = Map.objects.get(address=addr).value
                    logger.debug("File identifier: %s",cf)
                    
                    # Create list of values, which will be used to identify json-id
                    #Cfw.append(cf)
                    
                    # Retrieve ciphertexts
                    ct = CipherText.objects.filter(jsonId=cf).values()
                    logger.debug("Ciphertext of the same file: %s",ct)
                    CipherL.append(list(ct))
                    
                    # Delete the current (address, value) and update with the new (address, value)
                    Map.objects.get(address=addr).delete()
                    logger.debug("New address: %s",Lu[i-1])
                    Map.objects.create(address=Lu[i-1],value=cf) # fileno == length(Lu)
                except:
                    logger.debug("Not found: %s",addr)
                    cf = None
                        
#             bundle.obj.Cfw = Cfw
            bundle.obj.Cfw = CipherL
            logger.debug("The list of ciphertext: %s",CipherL)
           # bundle.obj.Cfw = CipherL
            bundle.obj.KeyW = '' # hide KeyW in the response
            bundle.obj.fileno = 0 # hide fileNo in the response  
            bundle.obj.Lu=[]     # hide Lu in the response  
#             logger.debug("Send list of addresses (Cfw) back to the user:", bundle)
            logger.debug("Send list of ciphertext (Cfw) back to the user: %s", bundle)
        else:
            logger.debug("Lu!=Lta")
        
 
        return bundle
