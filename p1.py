import io
import json


def read_varint(stream):
    variant = int.from_bytes(stream.read(1))
    if variant <= 0xFC:
        output = variant
    if variant == 0xFD:
        output = int.from_bytes(stream.read(2),'little')
    if variant == 0xFE:
        output = int.from_bytes(stream.read(4),'little')
    if variant == 0xFF:
        output = int.from_bytes(stream.read(8),'little')
    return output

def script_type(scriptSig):
    script_length = len(scriptSig)
    if script_length == 25 and bytes.startswith(scriptSig,0x76a914) and bytes.endswith(scriptSig,0x88ac):
        return "P2PKH"
    elif script_length == 23 and bytes.startswith(scriptSig,0xa914) and bytes.endswith(scriptSig,0x87):
        return "P2SH"
    elif script_length == 22 and bytes.startswith(scriptSig,0x0014):
        return "P2WPKH"
    elif script_length == 34 and bytes.startswith(scriptSig,0x0020):
        return "P2WSH"
    elif script_length == 34 and bytes.startswith(scriptSig,0x5120):
        return "P2PTR"
    else:
        return "N/A"
        
def decode_tx(tx_string):
    # read bytes from the transaction
    tx_hex = bytes.fromhex(tx_string)
    tx_stream = io.BytesIO(tx_hex) 
    
    # read the version
    version = tx_stream.read(4)
    version = int.from_bytes(version,'little')
    
    # read the marker
    marker = tx_stream.read(1)
    marker = int.from_bytes(marker)
    if marker == 0:
        flag = tx_stream.read(1)
        flag = int.from_bytes(flag)
    else:
        tx_stream.seek(-1,io.SEEK_CUR)

    # input count (variable size)
    input_count = read_varint(tx_stream)

    # reading inputs
    v_inputs=[]
    for v_in in range(input_count):
        # txid
        temp_txid = tx_stream.read(32)[::-1].hex()
        # vout
        temp_vout = tx_stream.read(4)
        temp_vout = int.from_bytes(temp_vout,'little')
        
        # script size
        script_size = read_varint(tx_stream)
        script_content = tx_stream.read(script_size).hex()
        
        # sequence
        sequence = int.from_bytes(tx_stream.read(4),'little')
        # assemble vinputs
        temp_input = {
            "txid": temp_txid, 
            "vout": temp_vout, 
            "scriptsig_size":script_size, 
            "scriptsig":script_content,
            "sequence":hex(sequence)
            }
        v_inputs.append(temp_input)

    # output count
    output_count = read_varint(tx_stream)

    # reading outputs
    v_outputs=[]
    for v_out in range(output_count):
        # amount
        amount = int.from_bytes(tx_stream.read(8),'little')
        # Script PubKey Size
        spk_size = read_varint(tx_stream)
        spk = tx_stream.read(spk_size)
        spk_tag = script_type(spk)
        # assemble v_out
        temp_output = {
            "amount": amount,
            "scriptType":spk_tag,
            "scriptPubKey":spk.hex()
        }
        v_outputs.append(temp_output)

    # reading the witness
    if marker == 0:
        for v_in in range(input_count):
            stack_items = read_varint(tx_stream)
            items = []
            for stack_item in range(stack_items):
                stack_size = read_varint(tx_stream)
                item = tx_stream.read(stack_size)
                items.append(item.hex())
            v_inputs[v_in]["witness"] = items

    # reading the locktime
    locktime = int.from_bytes(tx_stream.read(4),'little')

    # check to see if nothing leftovers
    data_leftover = tx_stream.read()
    if not data_leftover:
        return {
            "version": version,
            "Marker": marker,
            "Flag": flag if marker==0 else "n/a",
            "Input Count": input_count,
            "Inputs": v_inputs,
            "Output Count": output_count,
            "Outputs": v_outputs,
            "Locktime": locktime
            
        }
    else: 
        raise ValueError(f"Transaction not read properly. Data was leftover: {len(data_leftover)} bytes. \n Data: ({data_leftover})")
        

 


def main():
    path = "tx.txt"
    content = ""
    with open(path, "r", encoding="utf-8") as file:
        content = file.read()
    # print(content)
    # read transaction bytes
    tx_bytes = content.strip()
    try:
        decoded_transaction= decode_tx(tx_bytes)
        print(json.dumps(decoded_transaction,indent=2))
    except ValueError as error:
        print(error)
    
if __name__ == "__main__":
    main()