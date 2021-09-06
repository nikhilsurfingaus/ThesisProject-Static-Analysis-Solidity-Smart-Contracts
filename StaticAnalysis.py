#Checks for compiler version bug
def compiler_issue(file):
    code = enumerate(open(file))
    bug = "^"
    for i, line in code:
        if bug in line:
            print("\nCompiler Bug Detected at Line: " + str(i + 1))
            print("Solution: Remove ^ operator as future compilers may have unintended effects")
            print("Risk: Medium\n")

#Checks for Underflow/Overflow bug
#Underflow/Overflow Check 1
def check_safe_math(file):
    code = enumerate(open(file))
    library = "using SafeMath for uint"
    integer = "uint"
    safe = False
    function_current = True
    start = True
    end_val = "}"
    for i, line in code:
        if end_val in line:
            #Next Code Segment
            function_current = True
            start = False
        else:
            start = True
        
        if (integer in line) and (safe == False) and (start == True):
            if library in line:
                function_current = False
                #Already using SafeMath Lib

        if (integer in line) and (safe == False) and (start == True):
            if (library not in line) and (function_current == True):
                #Not using SafeMath Lib
                print("\nInteger Overflow/Underflow Bug Detected at Line: " + str(i + 1))
                print("Solution: Use SafeMath library to minimise vulnerbaility")
                print("Risk: High\n")

#Underflow/Overflow Check 2
def check_integer_operations(file):
    code = enumerate(open(file))
    pos_inc = "++)"
    neg_inc = "--)"
    ma_lib = ["+", "-", "*", "/", "%"]
    ma_lib_name = {"+":".add", "-":".sub", "*":".mul", "/":".div", "%":".mod"}   
    for i, line in code:
        for op in ma_lib:
            if ((pos_inc or neg_inc) not in line) and (op in line):    
                print("\nInteger Overflow/Underflow Bug Detected at Line: " + str(i + 1))
                print("Solution: Use SafeMath library operation " + ma_lib_name[op] + " to minimise vulnerbaility")
                print("Risk: High\n")
    
#Underflow/Overflow Check 3 Check before Transfer
#Underflow/Overflow Check 4 Check x
#Underflow/Overflow Check 5 Check y
#Underflow/Overflow Check 6 Check z

#Checks for Unhadled Exceptions bug
#Unhadled Exceptions Check 1
def check_transfer(file):
    code = enumerate(open(file))
    bug_1 = ".send("
    bug_2 = "call.value"
    for i, line in code:
        if bug_1 in line:
            print("\nUnhadled Exceptions Bug Detected at Line: " + str(i + 1))
            print("Solution: Use transfer function instead of send operation as send doesn't capture \
                \ntransaction fails to minimise vulnerbaility")
            print("Risk: Medium\n")      
        elif bug_2 in line:
            print("\nUnhadled Exceptions Bug Detected at Line: " + str(i + 1))
            print("Solution: Use transfer function operation since call has no gas limit to minimise vulnerbaility")
            print("Risk: High\n")            
#Unhadled Exceptions Check 1
#Unhadled Exceptions Check 1
#Unhadled Exceptions Check 1

#Storage Issue
#Check 1 Byte Storage
def check_bytes(file):
    code = enumerate(open(file))
    pattern = "bytes"
    pattern_variant = "byte"
    key_array = "[]"
    for i, line in code:
        if (((pattern in line) and (key_array in line)) or ((pattern_variant in line) and (key_array in line))):
            print("\nStorage Bug Detected at Line: " + str(i + 1))
            print("Solution: Use bytes instead of bytes[] array to minimise vulnerbaility")
            print("Risk: Low\n")       




#Checks for Authentication bug
#Authentication Check 1
def check_tx_origin(file):
    code = enumerate(open(file))
    bug = "tx.origin"
    for i, line in code:
        if bug in line:
            print("\nAuthentication Bug Detected at Line: " + str(i + 1))
            print("Solution: Use msg.sender instead of tx.origin to minimise vulnerbaility")
            print("Risk: High\n")  
            
#Checks for Visibility bug
#Visibility Check 1
def check_function_visibility(file):
    code = enumerate(open(file))
    type_1 = "public"
    type_2 = "private"
    keyword = "function"
    for i, line in code:
        if (keyword in line) and not((type_1 in line) or (type_2 in line)):
            print("\nVisibility Bug Detected at Line: " + str(i + 1))
            print("Solution: Use public/private specifier when defining function to minimise vulnerbaility")
            print("Risk: High\n") 
 
#Checks for Equality bug
#Visibility Check 1
def check_balance_equality(file):
    code = enumerate(open(file))
    bug = ".balance =="
    for i, line in code:
        if bug in line:
            print("\nEquality Bug Detected at Line: " + str(i + 1))
            print("Solution: Use public/private specifier when defining function to minimise vulnerbaility")
            print("Risk: High\n") 

#Checks for Randomness bug
#Randomness Check 1
def check_block_timestamp(file):
    code = enumerate(open(file))
    bug = "block.timestamp"
    for i, line in code:
        if bug in line:
            print("\nRandomness Bug Detected at Line: " + str(i + 1))
            print("Solution: Avoid block.randomness for randomness to minimise DoS vulnerbaility")
            print("Risk: Medium\n") 

#Randomness Check 2
def check_block_variable(file):
    code = enumerate(open(file))
    bug_coin = "block.coinbase"
    bug_gas = "block.gaslimit"
    bug_diff = "block.difficulty"
    
    for i, line in code:
        if ((bug_coin in line) or (bug_gas in line) or (bug_diff in line)):
            print("\nBlock Variable Dependency Bug Detected at Line: " + str(i + 1))
            print("Solution: Potenital leaky PRNGS rely heavily on past block hashes future vulnerbility")
            print("Risk: Low\n") 

#Randomness Check 3
def check_block_number(file):
    code = enumerate(open(file))
    bug = "block.number"
    
    for i, line in code:
        if (bug in line):
            print("\nBlock Number Dependency Bug Detected at Line: " + str(i + 1))
            print("Solution: Check function not send/transfer, can be manipulated by attackers")
            print("Risk: Low\n") 
            
#Checks for Delegate Call bug
def check_delegate_call(file):
    code = enumerate(open(file))
    bug = "delegatecall"
    bug_var = "DelegateCall"
    for i, line in code:
        if ((bug in line) or (bug_var in line)):
            print("\nDelegate Call Bug Detected at Line: " + str(i + 1))
            print("Solution: Avoid Delegate Call this can lead to unexpected code execution vulnerbaility")
            print("Risk: Low\n") 

#Function Calls inside a loop
def check_loop_function(file):
    code = enumerate(open(file))
    loop_for = "for"
    loop_while = "while"
    bug = "."
    function_current = False
    loop_start = False
    end_val = "}"
    for i, line in code:
        
        if (bug in line) and (function_current == True):
            print("\nFor/While Loop Function Call Bug Detected at Line: " + str(i + 1))
            print("Solution: Avoid Function Call In For/While Loop possible DoS vulnerbaility")
            print("Risk: Low\n")   
       
        if ((loop_for in line) or (loop_while in line)):
            function_current = True
            loop_start = True            

        if (end_val in line) and (loop_start == True):
            #Next Function 
            function_current = False
            loop_start = False

#Block Gas Limit
def check_block_gas(file):
    code = enumerate(open(file))
    bug = "length"
    loop_for = "for"
    loop_while = "while"
    for i, line in code:
        if (((loop_for in line) and (bug in line)) or ((loop_while in line) and (bug in line))):
            print("\nBlock Gas Limit Bug Detected at Line: " + str(i + 1))
            print("Solution: Avoid loop of unknown size that could grow and cause DoS vulnerability")
            print("Risk: High\n")  
            
#Pyable Fallback
def check_fallback(file):
    code = enumerate(open(file))
    key = "function"
    mark = "payable"
    left = 'function '
    right = '('
    for i, line in code:
        if (key in line):
            name = line[line.index(left)+len(left):line.index(right)]
            if ((len(name) == 0) and (mark not in line)):
                print("\nPayable Fallback Bug Detected at Line: " + str(i + 1))
                print("Solution: Mark Fallback function with payable otherwise contract cannot recieve ether")
                print("Risk: Medium\n")  

#COMPLEX CHECKS
#DAO Attack Vulnerability
#Reentracy Check 1
# Using a modifier blockRentrancy: the idea is to lock the contract while any 
# function of the contract is being executed, so only a single function in the contract can be executed at a time.
def check_contract_lock(file):
    code = enumerate(open(file))
    #Name either blockreeracy or reentracy guard locks the contract


#Reentracy Check 2a
#Check require condtion is met
def check_withdraw_a(file, func_name, state_var, with_amount_var):
    code = enumerate(open(file))
    bigger_equals = ">="
    less_equals = "<="
    keyword = "require"
    start = False
    start_char = "{"
    end_char = "}"
    line_var = 0;
    found = False
    for i, line in code:
        if ((func_name in line) and (start_char in line)):
            start = True
            line_var = i + 1
            
        if ((end_char in line) and  (start_char not in line) and (found == False)):
            start = False
            print("\nWithdraw Function Call Bug Detected at Line: " + str(line_var))
            print("Solution: We need this to check require balance and amount first")
            print("Risk: Medium\n")  
            
        if ((end_char in line) and  (start_char not in line) and (found == True)):
            start = False
            found = False;
            
        if ((keyword in line) and (state_var in line) and (with_amount_var in line) and (start == True)):
            if ((bigger_equals in line) or (less_equals in line)):
                found = True

#Reentracy Check 2b
#Update state variable before call to prevent reetrancy multiple calls from attacker   
def check_withdraw_b(file, func_name, state_var, with_amount_var):
    code = enumerate(open(file))
    found = False
    call_made = False
    subtract = "-"
    call = "msg.sender.call"
    send = "msg.sender.send"
    transfer = "msg.sender.transfer"
    
    for i, line in code:
        if(((call in line) or (send in line) or (transfer in line)) and (with_amount_var in line) and (found == False)):
            call_made = True
            print("\nWithdraw Function Call Bug Detected at Line: " + str(i +1))
            print("Solution: Update state variable balance before call")
            print("Risk: High\n")  
          
        if ((call_made == False) and (state_var in line) and (with_amount_var in line) and (subtract in line)):
            found = True

#Reentracy Check 3
#Check External Call
def check_external_call(file):
    code = enumerate(open(file))
    keyword = "external"
    keyword_trust = "trusted"
    keyword_un_trust = "untrusted"
    keyword_func = "function"
    start = False
    end = "}"
    for i, line in code:
        if ((keyword_func in line) and (keyword_un_trust in line)):
            print("\nUntrusted Function Bug Detected at Line: " + str(i +1))
            print("Solution: Be aware that subsequent calls also inherit untrust state")
            print("Risk: low\n") 
        
        #Bad Case external call is untrusted
        if ((end in line) and (len(line) <= 2)):
            start = False
                
        if ((start == True) and (keyword_un_trust in line)):
            print("\nUntrusted Function External Call Bug Detected at Line: " + str(i +1))
            print("Solution: Be aware that subsequent calls also inherit untrust state")
            print("Risk: High\n") 
            
        if ((keyword_func in line) and (keyword in line)):
            start = True
        
        #Check Label
        if ((keyword_func in line) and (keyword_trust not in line) and (keyword_un_trust not in line)):
            print("\nUntrusted Function Bug Detected at Line: " + str(i +1))
            print("Solution: Unknown trust, label function either trusted/untrusted")
            print("Risk: Medium\n") 
        

#Checks-effects-interactions pattern
def check_effects_interactions_pattern(file):
    code = enumerate(open(file))
    check_one = "require"
    check_two = "assert"
    new_function = "function"
    update = "="
    start = False
    end = "}"    
    inter_send = "send"
    inter_trans = "transfer"
    inter_call = "call"
    
    first = False
    Second = False
    third = False
    
    check_found = False
    effect_found = False
    interact_found = False
    
    single_check = False
    single_effect = False
    single_interact = False
    
    function_line = 0;

    for i, line in code:
        #Move onto next function
        if ((end in line) and (len(line) <= 2) and (start == True)):
            #Output Phase
            #Check Missing
            if (check_found == False):
                print("\nCheck-Effect-Interaction Bug Detected at Line: " + str(function_line))
                print("Solution: Check is missing")
                print("Risk: Medium\n")   
            #Check Order
            if (single_check == True):
                print("\nCheck-Effect-Interaction Bug Detected at Line: " + str(function_line))
                print("Solution: Check is out of order")
                print("Risk: Medium\n")  
            #Effect Order
            if ((effect_found == False) and (single_effect == False)):
                print("\nCheck-Effect-Interaction Bug Detected at Line: " + str(function_line))
                print("Solution: Effect is missing")
                print("Risk: Medium\n")   
            #Effect Missing     
            if (single_effect == True):
                print("\nCheck-Effect-Interaction Bug Detected at Line: " + str(function_line))
                print("Solution: Effect is out of order")
                print("Risk: Medium\n")  
            #Interact Missing
            if ((interact_found == False) and (single_interact == False)):
                print("\nCheck-Effect-Interaction Bug Detected at Line: " + str(function_line))
                print("Solution: Interact is missing")
                print("Risk: Medium\n")              
            #Interact Order
            if (single_interact == True):
                print("\nCheck-Effect-Interaction Bug Detected at Line: " + str(function_line))
                print("Solution: Interact is out of order")
                print("Risk: Medium\n")      
            #Reset Variables
            start = False
            first = False
            Second = False
            third = False
            check_found = False
            effect_found = False
            interact_found = False
            single_check = False
            single_effect = False
            single_interact = False
            function_line = 0;
        #Come accross new function
        if ((new_function in line) and (start == False)):
            start = True 
            first = True  
            function_line = i + 1
        #Check Phase
        if (((check_one in line) or (check_two in line)) and (first == True)):
            check_found = True
            Second = True
        #Check Phase out of order
        if((Second == False) and ((check_one in line) or (check_two in line))):
            single_check = True;
        #Effect Phase
        if ((Second == True) and (update in line)):
            effect_found = True
            third = True
        #Effect But no Check
        if ((update in line) and (Second == False)):
            single_effect = True        
            #Interact Phase
        if ((third == True) and ((inter_call in line) or (inter_send in line) or (inter_trans in line))):
            interact_found = True
        #Interact But no Check/Effect
        if (((inter_call in line) or (inter_send in line) or (inter_trans in line)) and (third == False)):
            single_interact = True 


#Reentracy Check 4
#Cross Function reentracy

#Reentracy Check 5
#Interleaving Hazards


def main():
    file = "Tests/compilerissue.txt"
    file2 = "Tests/overflowunderflowissue.txt"
    file3 = "Tests/overflowunderflowissue2.txt"
    file4 = "Tests/exceptionissue1.txt"
    file5 = "Tests/authenticationissue1.txt"
    file6 = "Tests/visibilityissue.txt"
    file7 = "Tests/equalityissue1.txt"
    file8 = "Tests/timestampissue.txt"
    file9 = "Tests/delegatecallissue.txt"
    file10 = "Tests/loopfunctiondos.txt"
    file11 = "Tests/bytesissue.txt"
    file12 = "Tests/blockvar.txt"
    file13 = "Tests/blocknum.txt"
    file14 = "Tests/blockgas.txt"
    file15 = "Tests/fallbackpay.txt"
    #Simple Checks
    compiler_issue(file)
    check_safe_math(file2) 
    check_integer_operations(file3)   
    check_transfer(file4)
    check_tx_origin(file5)
    check_function_visibility(file6)
    check_balance_equality(file7)
    check_block_timestamp(file8)
    check_delegate_call(file9)
    check_loop_function(file10)
    check_bytes(file11)
    check_block_variable(file12)
    check_block_number(file13)
    check_block_gas(file14)
    check_fallback(file15)
    #Complex Checks
  
    # #Ask for User Input On These
    withdraw_function = "withdraw"
    balance_state_variable = "balances"
    withdraw_amount = "_amount"
    comp_file = "Tests/reentracyissue.txt"

    #Reentracy Check 2
    check_withdraw_a(comp_file, withdraw_function, balance_state_variable, withdraw_amount)
    
    #Reentracy Check 1
    check_withdraw_b("Tests/testret.txt", withdraw_function, balance_state_variable, withdraw_amount)
    check_withdraw_b("Tests/testret1.txt", withdraw_function, balance_state_variable, withdraw_amount)

    #Reentracy Check 3
    externalfile = "Tests/externalissue.txt"
    check_external_call(externalfile)
    
    # #Reentracy Check 3
    CEIfile = "Tests/checkeffectinteractissue.txt"
    check_effects_interactions_pattern(CEIfile)

    #print("\n----------------------------------------")
    #Experiment 1
    #compiler_issue("exp1.txt")
    #check_safe_math("exp1.txt") 
    #check_integer_operations("exp1.txt")   
    #check_transfer("exp1.txt")
    #check_tx_origin("exp1.txt")
    #check_function_visibility("exp1.txt")
    #check_balance_equality("exp1.txt")
    #check_block_timestamp("exp1.txt")
    #check_delegate_call("exp1.txt")
    #check_loop_function("exp1.txt")
    #check_bytes("exp1.txt")

    #check_external_call("exp1.txt")
    #check_effects_interactions_pattern("exp1.txt")


    #Score
    score = 0
    

if __name__ == "__main__":
    main()