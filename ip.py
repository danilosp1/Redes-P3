from iputils import *
from ipaddress import ip_network, ip_address
import struct
from grader.tcputils import calc_checksum, str2addr

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.table = {}
        self.id = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            if ttl <= 1:
                # Gera e envia uma mensagem ICMP Time Exceeded de volta ao remetente
                self.__send_icmp_time_exceeded(src_addr, datagrama)
            else:
                # Decrementa o TTL e encaminha o datagrama
                ttl -= 1
                # Recalcula o checksum do cabeçalho com o TTL decrementado
                new_header = self.__update_header(datagrama[:20], ttl)
                new_datagram = new_header + datagrama[20:]
                next_hop = self._next_hop(dst_addr)
                self.enlace.enviar(new_datagram, next_hop)
    
    def __update_header(self, header, ttl):
        # Desempacota o cabeçalho original, atualiza o TTL e recalcula o checksum
        versao_IHL, tipo_de_servico, comprimento_total, identificacao, \
        flags_offset, _, proto, _, src_addr_bin, dest_addr_bin = struct.unpack("!BBHHHBBH4s4s", header)
        
        checksum = 0  # Zera o checksum para recálculo
        # Reempacota o cabeçalho com o TTL atualizado e sem checksum
        header_sem_checksum = struct.pack("!BBHHHBBH4s4s", versao_IHL, tipo_de_servico, comprimento_total,
                                        identificacao, flags_offset, ttl, proto, checksum,
                                        src_addr_bin, dest_addr_bin)
        # Calcula o novo checksum
        checksum = calc_checksum(header_sem_checksum)
        # Reempacota o cabeçalho com o novo checksum
        new_header = struct.pack("!BBHHHBBH4s4s", versao_IHL, tipo_de_servico, comprimento_total,
                                identificacao, flags_offset, ttl, proto, checksum,
                                src_addr_bin, dest_addr_bin)
        return new_header
    
    def __send_icmp_time_exceeded(self, src_addr, datagrama):
        # Constrói uma mensagem ICMP Time Exceeded
        tipo_icmp = 11  # Time Exceeded
        codigo = 0  # Time to Live exceeded in Transit
        checksum = 0
        unused = 0
        # Inclui o cabeçalho IP original e os primeiros 8 bytes do datagrama causador
        data = datagrama[:28]
        icmp_header = struct.pack("!BBHI", tipo_icmp, codigo, checksum, unused)
        icmp_payload = icmp_header + data
        # Calcula o checksum do pacote ICMP
        checksum = calc_checksum(icmp_payload)
        # Reconstroi o pacote ICMP com o checksum calculado
        icmp_payload = struct.pack("!BBHI", tipo_icmp, codigo, checksum, unused) + data
        
        # Agora, constroi o cabeçalho IP para o datagrama ICMP
        versao_IHL = (4 << 4) | 5
        tipo_de_servico = 0
        comprimento_total = 20 + len(icmp_payload)  # Cabeçalho IP + payload ICMP
        identificacao = 0  # Pode ser zero para mensagens de erro ICMP
        flags_offset = 0
        ttl = 64  # TTL padrão para datagramas ICMP
        protocolo = 1  # Protocolo ICMP
        checksum = 0 
        src_addr_bin = struct.pack("!I", int(ip_address(self.meu_endereco)))
        dest_addr_bin = struct.pack("!I", int(ip_address(src_addr)))
        # Monta o cabeçalho IP sem o checksum para cálculo
        ip_header_sem_checksum = struct.pack("!BBHHHBBH4s4s",
                                            versao_IHL, tipo_de_servico, comprimento_total,
                                            identificacao, flags_offset, ttl, protocolo,
                                            checksum, src_addr_bin, dest_addr_bin)
        # Calcula o checksum do cabeçalho IP
        checksum = calc_checksum(ip_header_sem_checksum)
        # Monta o cabeçalho IP final com checksum
        ip_header = struct.pack("!BBHHHBBH4s4s",
                                versao_IHL, tipo_de_servico, comprimento_total,
                                identificacao, flags_offset, ttl, protocolo,
                                checksum, src_addr_bin, dest_addr_bin)
        
        # Combina o cabeçalho IP com o payload ICMP para formar o datagrama completo
        icmp_datagrama = ip_header + icmp_payload
        
        # Envia o datagrama ICMP de volta ao remetente
        next_hop = self._next_hop(src_addr)
        self.enlace.enviar(icmp_datagrama, next_hop)

    def _next_hop(self, dest_addr):
        dest_ip = ip_address(dest_addr)
        melhor_correspondencia = None
        maior_prefixo = -1
        for cidr, next_hop in self.tabela_encaminhamento:
            network = ip_network(cidr, strict=False)  # Converte a string CIDR em um objeto de rede IP
            if dest_ip in network:  # Verifica se o IP de destino está dentro da rede
                # Verifica se esta correspondência tem um prefixo mais longo que a melhor até agora
                if network.prefixlen > maior_prefixo:
                    melhor_correspondencia = next_hop 
                    maior_prefixo = network.prefixlen
        return melhor_correspondencia

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela_encaminhamento = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def datagrama(self, segmento, dest_addr, aux):
        if(0 == len(aux)):
            src_addr = self.meu_endereco  # Endereço IP de origem

            # Monta o cabeçalho IP
            versao_IHL = (4 << 4) | 5
            tipo_de_servico = 0
            comprimento_total = 20 + len(segmento)  # 20 bytes de cabeçalho + comprimento do segmento
            identificacao = self.id
            flags_offset = 0
            ttl = 64
            protocolo = 6  # TCP
            checksum = 0  # Será calculado depois
            src_addr_bin = struct.pack("!I", int(ip_address(src_addr)))
            dest_addr_bin = struct.pack("!I", int(ip_address(dest_addr)))
            self.id += comprimento_total
        else:
            versao_IHL, tipo_de_servico, comprimento_total, identificacao, flags_offset, ttl, protocolo, checksum, src_addr_bin, dest_addr_bin = aux
            ttl = ttl-1

         # Primeira parte do cabeçalho sem checksum
        cabecalho_sem_checksum = struct.pack("!BBHHHBBH4s4s",
                                             versao_IHL, tipo_de_servico, comprimento_total,
                                             identificacao, flags_offset, ttl, protocolo,
                                             checksum, src_addr_bin, dest_addr_bin)

         # Calcula o checksum
        checksum = calc_checksum(cabecalho_sem_checksum)
        # Monta o cabeçalho final com checksum
        cabecalho = struct.pack("!BBHHHBBH4s4s",
                                versao_IHL, tipo_de_servico, comprimento_total,
                                identificacao, flags_offset, ttl, protocolo,
                                checksum, src_addr_bin, dest_addr_bin)

        # Monta o datagrama completo
        datagrama = cabecalho + segmento

        return datagrama


    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        
        next_hop = self._next_hop(dest_addr)  # Próximo salto

        datagrama = self.datagrama(segmento, dest_addr, [])
        
        self.enlace.enviar(datagrama, next_hop)