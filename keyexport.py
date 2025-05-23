from pysros.management import connect
import re
import configargparse


class SRConnection:
    def __init__(self,router,netconf_port,netconf_user,netconf_passwd):
        self.connection = connect(host=router,port=netconf_port, username=netconf_user, password=netconf_passwd,hostkey_verify=False)


    def get_tunnel_remote_eps(self,svc,gw,idi_pattern):  
        """return a list of tunnel remote endpoints that terminate on the specified gateway and its IDi matches with idi_pattern
        endpoint is tuple of two items, first is the IP addr, 2nd is the port
        """
        #try ies first
        reps=[]
        path_prefix = '/nokia-state:state/service/ies[service-name="{}"]/interface'
        if_names = self.connection.running.get_list_keys(path_prefix.format(svc))
        if len(if_names)==0:
            #try vprn 
            path_prefix = '/nokia-state:state/service/vprn[service-name="{}"]/interface'
            if_names = self.connection.running.get_list_keys(path_prefix.format(svc))
            if len(if_names)==0:
                raise ValueError("can't find service {}".format(svc))
        for ifname in if_names:
            sap = self.connection.running.get_list_keys(path_prefix.format(svc)+'[interface-name="{}"]/sap'.format(ifname))
            if len(sap)>0:
                if re.match(r'^tunnel-\d+\.public:\d+$',sap[0]): #if it is public tunnel-sap
                    gwnames = self.connection.running.get_list_keys(path_prefix.format(svc)+'[interface-name="{}"]/sap[sap-id="{}"]/ipsec-gateway'.format(ifname,sap[0]))
                    if len(gwnames)>0:
                        if gwnames[0]==gw: #found the gw
                            eps = self.connection.running.get_list_keys(path_prefix.format(svc)+'[interface-name="{}"]/sap[sap-id="{}"]/ipsec-gateway[name="{}"]/dynamic-tunnel'.format(ifname,sap[0],gw))
                            for ep in eps:
                                idi = self.connection.running.get(path_prefix.format(svc)+'[interface-name="{}"]/sap[sap-id="{}"]/ipsec-gateway[name="{}"]/dynamic-tunnel[address="{}"][port="{}"]/ike-idi-value'.format(ifname,sap[0],gw,ep[0],ep[1]))
                                if re.search(idi_pattern,idi.data)!=None:
                                    reps.append(ep)
        return reps
    
    def get_ike_key_table_bytes(self,gw,eps):
        """return a tuple of two items, first is a str of list of IKE key info of tunnels terminated on gw, specified by endpoints in list eps, in wireshark isakmp key file format,
        2nd item is a wireshark display filter filter out IKEv2 packet with initiator SPI is one of these tunnels
        """
        enc_alg_dict = {
            'aes128': 'AES-CBC-128 [RFC3602]',
            'aes192': 'AES-CBC-192 [RFC3602]',
            'aes256': 'AES-CBC-256 [RFC3602]',
            'aes128gcm8': 'AES-GCM-128 with 8 octet ICV [RFC5282]',
            'aes128gcm16': 'AES-GCM-128 with 16 octet ICV [RFC5282]',
            'aes256gcm8': 'AES-GCM-256 with 8 octet ICV [RFC5282]',
            'aes256gcm16': 'AES-GCM-256 with 16 octet ICV [RFC5282]',
        }
        hash_alg_dict = {
            'sha256': 'HMAC_SHA2_256_128 [RFC4868]',
            'sha1':'HMAC_SHA1_96 [RFC2404]',
            'sha384':'HMAC_SHA2_384_192 [RFC4868]',
            'sha512':'HMAC_SHA2_512_256 [RFC4868]',

        }
        none_hash_alg = 'NONE [RFC4306]'
        keyrs=""
        dfrs = "isakmp.ispi in {"
        for ep in eps:
            records = self.connection.action('/nokia-oper-admin:admin/ipsec/show/key', {'type':'ike','gateway':gw,'peer-tunnel-ip-address':ep[0], 'peer-tunnel-port': ep[1]})
            for record in records['results']['key-history'].values():
                    dfrs += "{},".format(record['initiator-spi'])
                    enc_alg = enc_alg_dict.get(record['responder-encryption-key']['algorithm'].data)
                    if enc_alg == None:
                        raise ValueError("{} is not a supported encryption alg",record['responder-encryption-key']['algorithm'].data)
                    if enc_alg.find("GCM")>0: # GCM 
                        hash_alg = none_hash_alg
                    else:
                        hash_alg = hash_alg_dict.get(record['responder-authentication-key']['algorithm'].data)
                        if hash_alg == None:
                            raise ValueError("{} is not a supported encryption alg",record['responder-authentication-key']['algorithm'].data)
                    if hash_alg!=none_hash_alg:
                        keyrs += '{ispi},{rspi},{sk_ei},{sk_er},"{enc}",{sk_ai},{sk_ar},"{hash}"\n'.format(
                            ispi=record['initiator-spi'],rspi=record['responder-spi'],sk_ei=record['initiator-encryption-key']['key-hex'],
                            sk_er=record['responder-encryption-key']['key-hex'],enc=enc_alg,
                            sk_ai=record['initiator-authentication-key']['key-hex'],sk_ar=record['responder-authentication-key']['key-hex'],hash=hash_alg)
                    else:
                        keyrs += '{ispi},{rspi},{sk_ei},{sk_er},"{enc}",,,"{hash}"\n'.format(
                            ispi=record['initiator-spi'],rspi=record['responder-spi'],sk_ei=record['initiator-encryption-key']['key-hex'],
                            sk_er=record['responder-encryption-key']['key-hex'],enc=enc_alg,hash=hash_alg)

        dfrs=dfrs[:-1]+"}"
        return keyrs,dfrs
    
def main():
    p = configargparse.ArgParser(default_config_files=['~/.srosipseckeyexportor.conf'])
    p.add('-t','--router',required=True,help="router's IP")
    p.add('--port',required=False, type= int,help="router's netconf port",default=830)
    p.add('-u','--user',required=True,help="netconf username")
    p.add('-p','--passwd',required=True,help="netconf password")
    p.add('-s','--svc',required=True,help="name of service where ipsec-gateway is in")
    p.add('-g','--gw',required=True,help="ipsec-gateway name")
    p.add('-i','--idi',required=True,help="IDi RE match pattern")
    p.add('-o','--output',required=False, default="", help="output path of wireshark IKEv2 keyfile, use stdout if not specified")
    options = p.parse_args()

    src = SRConnection(options.router,options.port,options.user,options.passwd)
    eps = src.get_tunnel_remote_eps(options.svc,options.gw,options.idi)
    if len(eps)==0:
        print("no matching tunnel found")
        return
    keyrs,filters = src.get_ike_key_table_bytes("rw300",eps)
    if keyrs == "":
        print("no cached key found")
        return 
    if options.output=="":
        print("ikev2_decryption_table:\n{}".format(keyrs))
    else:
        with open(options.output, "w") as file:
            file.write(keyrs)
        print("keys are written to {}\n".format(options.output))
    print("wireshark display filter:\n{}".format(filters))

if __name__ == "__main__":
    main()