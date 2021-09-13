import numpy as np

#Checks for compiler version bug
def compiler_issue(file):
    code = enumerate(open(file))
    bug = "^"
    score = 0
    for i, line in code:
        if bug in line:
            print("\nCompiler Bug Detected at Line: " + str(i + 1))
            print("Solution: Remove ^ operator as future compilers may have unintended effects")
            print("Risk: Medium\n")
            print("Confidence: ")
            score += 6
    return score

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
    score = 0
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
                score+=9
    return score

#Underflow/Overflow Check 2
def check_integer_operations(file):
    code = enumerate(open(file))
    pos_inc = "++)"
    neg_inc = "--)"
    ma_lib = ["+", "-", "*", "/", "%"]
    ma_lib_name = {"+":".add", "-":".sub", "*":".mul", "/":".div", "%":".mod"}   
    score = 0
    for i, line in code:
        for op in ma_lib:
            if ((pos_inc or neg_inc) not in line) and (op in line):    
                print("\nInteger Overflow/Underflow Bug Detected at Line: " + str(i + 1))
                print("Solution: Use SafeMath library operation " + ma_lib_name[op] + " to minimise vulnerbaility")
                print("Risk: High\n")
                score+=9
    return score

#Division before multiply
def check_div_multiply(file):
    code = enumerate(open(file))
    div_op = "/"
    div_op_safe = "div"
    mul_op = "*"
    mul_op_safe = "mul"
    outer = ")"
    inner = "("
    score = 0
    for i, line in code:
        if (((div_op in line) or (div_op_safe in line)) and ((mul_op in line) or (mul_op_safe in line))):
            if ((outer in line) and (inner in line)):
                content = line[line.find(inner)+len(inner):line.rfind(outer)]
                if ((div_op in content) or (div_op_safe in content)):
                    print("\nDivsion before multiply Bug Detected at Line: " + str(i + 1))
                    print("Solution: Re-Order expression with multiplication first as integer truncation \
                        \nwith loss of precision to minimise vulnerbaility")
                    print("Risk: Medium\n")  
                    score+= 6
    return score            
                    
#Dangerous Unary Expression Warning 
def check_unary(file):
    code = enumerate(open(file))
    bug_plus = "=+"
    bug_minus = "=-"
    bug_times = "=*"
    score = 0
    for i, line in code:
        if ((bug_plus in line) or (bug_minus in line) or (bug_times in line)):
            print("\nDangerous Unary Expression Bug Detected at Line: " + str(i + 1))
            print("Solution: Check correct use could have meant += or -= or *=")
            print("Risk: Low\n")  
            score += 3
    return score

#Boolean Constance Bug
def check_bool_const(file):
    code = enumerate(open(file))
    bug_one = "(false)"
    bug_two = "(true)"
    bug_three = "|| true"
    bug_four = "|| false"
    bug_five = "true ||"
    bug_six = "false ||"
    bug_seven = "&& true"
    bug_eight = "&& false"
    bug_nine = "true &&"
    bug_ten = "false &&"
    key = "if"
    var_one = " = true"
    var_two = " = false"
    score = 0
    for i, line in code:
        if ((bug_one in line) or (bug_two in line) or (bug_three in line) or (bug_four in line) or (bug_five in line)):
            print("\nBoolean Constant Bug Detected at Line: " + str(i + 1))
            print("Solution: Simplify condition or verify code is not a mistake in boolen const")
            print("Risk: Low\n")   
            score+= 3
                   
        if ((bug_six in line) or (bug_seven in line) or (bug_eight in line) or (bug_nine in line) or (bug_ten in line)):
            print("\nBoolean Constant Bug Detected at Line: " + str(i + 1))
            print("Solution: Simplify condition or verify code is not a mistake in boolen const")
            print("Risk: Low\n")   
            score+= 3

        if((key in line) and ((var_one in line) or (var_two in line))):
            print("\nBoolean Constant Bug Detected at Line: " + str(i + 1))
            print("Solution: Verify whether mistake of tautology")
            print("Risk: Low\n")   
            score+= 3
    return score

#Array Length Assignemnt 
def check_arr_length(file):
    code_first = enumerate(open(file))
    code_second = enumerate(open(file))
    inner = "[] "
    outer = ";"
    key = ".length"
    operator = "="
    names = np.array([])
    concat_names = np.array([])
    score = 0
    for i, line in code_first:
        if ((inner in line)):
            arrayname = line[line.find(inner)+len(inner):line.rfind(outer)]
            exists = False
            for value in names:
                if (value == arrayname):
                    exists = True      
            if (exists == False):
                names = np.append(names, arrayname)
                concat_names = np.append(concat_names, (arrayname + key))

    #Now we have the arrays check if length is set
    for i, line in code_second:
        for arr in concat_names:
            if ((arr in line) and (operator in line)): 
                print("\nArray Length Assignement Bug Detected at Line: " + str(i + 1))
                print("Solution: Don't set array length directly, add values as needed storage could be vulnerble")
                print("Risk: Medium\n") 
                score += 6
    return score  
#uninitialised storage var check not already coded this bro
def check_init_storage_var(file):
    code_first = enumerate(open(file))
    code_second = enumerate(open(file))
    inner = "struct"
    outer = " {" 
    req = "="
    req_end = ";"
    names = np.array([])
    var_one = "uint"
    var_two = "address"
    score = 0
    #Get all struct names
    for i, line in code_first:
        if (inner in line):
            struct_name = line[line.find(inner)+len(inner):line.rfind(outer)]
            exists = False
            for value in names:
                if (value == struct_name):
                    exists = True      
            if (exists == False):
                names = np.append(names, struct_name)
    #Look for uninitialised variables 
    for i, line in code_second:
        #Look for struct varibales 
        for var in names:
            if((var in line) and (req_end in line) and (req not in line)):
                print("\nUninitialised Storage Variable Bug Detected at Line: " + str(i + 1))
                print("Solution: Immediatly initalise storage variables could be ovveridded")
                print("Risk: High\n") 
                score += 9
        if((var_one in line) and (req_end in line) and (req not in line)):
                print("\nUninitialised Storage Variable Bug Detected at Line: " + str(i + 1))
                print("Solution: Immediatly initalise storage variables could be ovveridded")
                print("Risk: High\n") 
                score += 9
        if((var_two in line) and (req_end in line) and (req not in line)):
                print("\nUninitialised Storage Variable Bug Detected at Line: " + str(i + 1))
                print("Solution: Immediatly initalise storage variables could be ovveridded")
                print("Risk: High\n") 
                score += 9
    return score
#incorrect shift in assembely
def check_assemble_shift(file):
    code = enumerate(open(file))
    key = "assembly"
    end = "}"
    start = False
    shift = "shr"
    inner_one = "shr("
    outer_one = ","
    inner_two = ", "
    outer_two = ")"
    score = 0
    for i, line in code:
        if((start == True) and (end in line)):
            start = False
        if (key in line):
            start = True
        #If inside assemble call  
        if ((shift in line) and (start == True)): 
            char_one = line[line.find(inner_one)+len(inner_one):line.rfind(outer_one)]
            char_two = line[line.find(inner_two)+len(inner_two):line.rfind(outer_two)]
            if ((char_two.isnumeric() == True) and (char_one.isnumeric() is False )):
                print("\nIncorrect Shit In Assembly Bug Detected at Line: " + str(i + 1))
                print("Solution: Swap order of parametres in shift")
                print("Risk: High\n") 
                score += 9
    return score
#suicidel
#     NEED TO CHECK THAT FUNCTION IS PROTECTED BEFORE WE CAN SELF DESTRUCT
def check_self_destruct(file):
    code = enumerate(open(file))
    code_second = enumerate(open(file))

    key_func = "function"
    key_visibility = "public"
    bug = "selfdestruct"
    end = "}"
    length = 2
    current = False
    score = 0
    #Case 1 Address to another contract
    for i, line in code:
        if ((bug in line)):
            print("\nSelf Destruct Vulnerability Detected at Line: " + str(i + 1))
            print("Solution: Check that address is not used as could send ether to an attacker contract")
            print("Risk: Medium\n")          
            score += 6
    #Case 2 public function with selfdestruct
    for i, line in code_second:
        if ((current == True) and (len(line) <= length) and (end in line)):
            current = False
        if ((key_func in line) and (key_visibility in line)):
            current = True
        if ((current == True) and (bug in line)):
            print("\nSelf Destruct Vulnerability Detected at Line: " + str(i + 1))
            print("Solution: If using self detruct restrict access to function as not public")
            print("Risk: High\n") 
            score += 9
                
    #Case 3 revert
    return score


#Checks for Unhadled Exceptions bug
#Unhadled Exceptions Check 1
def check_transfer(file):
    code = enumerate(open(file))
    bug_1 = ".send("
    bug_2 = "call.value"
    score = 0
    for i, line in code:
        if bug_1 in line:
            print("\nUnhadled Exceptions Bug Detected at Line: " + str(i + 1))
            print("Solution: Use transfer function instead of send operation as send doesn't capture \
                \ntransaction fails to minimise vulnerbaility")
            print("Risk: Medium\n") 
            score +=6     
        elif bug_2 in line:
            print("\nUnhadled Exceptions Bug Detected at Line: " + str(i + 1))
            print("Solution: Use transfer function operation since call has no gas limit to minimise vulnerbaility")
            print("Risk: High\n")  
            score += 9
    return score          
            
#Storage Issue
#Check 1 Byte Storage
def check_bytes(file):
    code = enumerate(open(file))
    pattern = "bytes"
    pattern_variant = "byte"
    key_array = "[]"
    score = 0
    for i, line in code:
        if (((pattern in line) and (key_array in line)) or ((pattern_variant in line) and (key_array in line))):
            print("\nStorage Bug Detected at Line: " + str(i + 1))
            print("Solution: Use bytes instead of bytes[] array to minimise vulnerbaility")
            print("Risk: Low\n")     
            score += 3
    return score  

#Checks for Authentication bug
#Authentication Check 1
def check_tx_origin(file):
    code = enumerate(open(file))
    bug = "tx.origin"
    score = 0
    for i, line in code:
        if bug in line:
            print("\nAuthentication Bug Detected at Line: " + str(i + 1))
            print("Solution: Use msg.sender instead of tx.origin to minimise vulnerbaility")
            print("Risk: High\n")  
            score += 9
    return score
            
#Checks for Visibility bug
#Visibility Check 1
def check_function_visibility(file):
    code = enumerate(open(file))
    type_1 = "public"
    type_2 = "private"
    keyword = "function"
    score = 0
    for i, line in code:
        if (keyword in line) and not((type_1 in line) or (type_2 in line)):
            print("\nVisibility Bug Detected at Line: " + str(i + 1))
            print("Solution: Use public/private specifier when defining function to minimise vulnerbaility")
            print("Risk: High\n") 
            score += 9
    return score
 
#Checks for Equality bug
#Visibility Check 1
def check_balance_equality(file):
    code = enumerate(open(file))
    bug = ".balance =="
    score = 0
    for i, line in code:
        if bug in line:
            print("\nEquality Bug Detected at Line: " + str(i + 1))
            print("Solution: Use public/private specifier when defining function to minimise vulnerbaility")
            print("Risk: High\n") 
            score += 9
    return score

#Checks for Randomness bug
#Randomness Check 1
def check_block_timestamp(file):
    code = enumerate(open(file))
    bug = "block.timestamp"
    score = 0
    for i, line in code:
        if bug in line:
            print("\nRandomness Bug Detected at Line: " + str(i + 1))
            print("Solution: Avoid block.randomness for randomness to minimise DoS vulnerbaility")
            print("Risk: Medium\n") 
            score += 6
    return score

#Randomness Check 2
def check_block_variable(file):
    code = enumerate(open(file))
    bug_coin = "block.coinbase"
    bug_gas = "block.gaslimit"
    bug_diff = "block.difficulty"
    score = 0
    for i, line in code:
        if ((bug_coin in line) or (bug_gas in line) or (bug_diff in line)):
            print("\nBlock Variable Dependency Bug Detected at Line: " + str(i + 1))
            print("Solution: Potenital leaky PRNGS rely heavily on past block hashes future vulnerbility")
            print("Risk: Low\n") 
            score+= 3
    return score

#Randomness Check 3
def check_block_number(file):
    code = enumerate(open(file))
    bug = "block.number"
    score = 0
    for i, line in code:
        if (bug in line):
            print("\nBlock Number Dependency Bug Detected at Line: " + str(i + 1))
            print("Solution: Check function not send/transfer, can be manipulated by attackers")
            print("Risk: Low\n") 
            score += 3
    return score
            
#Checks for Delegate Call bug
def check_delegate_call(file):
    code = enumerate(open(file))
    bug = "delegatecall"
    bug_var = "DelegateCall"
    score = 0
    for i, line in code:
        if ((bug in line) or (bug_var in line)):
            print("\nDelegate Call Bug Detected at Line: " + str(i + 1))
            print("Solution: Avoid Delegate Call this can lead to unexpected code execution vulnerbaility")
            print("Risk: Low\n") 
            score += 3
    return score

#Function Calls inside a loop
def check_loop_function(file):
    code = enumerate(open(file))
    loop_for = "for"
    loop_while = "while"
    bug = "."
    function_current = False
    loop_start = False
    end_val = "}"
    score = 0
    for i, line in code:
        if (bug in line) and (function_current == True):
            print("\nFor/While Loop Function Call Bug Detected at Line: " + str(i + 1))
            print("Solution: Avoid Function Call In For/While Loop possible DoS vulnerbaility")
            print("Risk: Low\n")   
            score += 3
       
        if ((loop_for in line) or (loop_while in line)):
            function_current = True
            loop_start = True            

        if (end_val in line) and (loop_start == True):
            #Next Function 
            function_current = False
            loop_start = False
    return score

#Block Gas Limit
def check_block_gas(file):
    code = enumerate(open(file))
    bug = "length"
    loop_for = "for"
    loop_while = "while"
    score = 0
    for i, line in code:
        if (((loop_for in line) and (bug in line)) or ((loop_while in line) and (bug in line))):
            print("\nBlock Gas Limit Bug Detected at Line: " + str(i + 1))
            print("Solution: Avoid loop of unknown size that could grow and cause DoS vulnerability")
            print("Risk: High\n")  
            score += 9
    return score
            
#Pyable Fallback
def check_fallback(file):
    code = enumerate(open(file))
    key = "function"
    mark = "payable"
    left = 'function '
    right = '('
    score = 0
    for i, line in code:
        if (key in line):
            name = line[line.index(left)+len(left):line.index(right)]
            if ((len(name) == 0) and (mark not in line)):
                print("\nPayable Fallback Bug Detected at Line: " + str(i + 1))
                print("Solution: Mark Fallback function with payable otherwise contract cannot recieve ether")
                print("Risk: Medium\n")  
                score += 6
    return score

#COMPLEX CHECKS
#DAO Attack Vulnerability
#Reentracy Check 1
# Using a modifier blockRentrancy: the idea is to lock the contract while any 
# function of the contract is being executed, so only a single function in the contract can be executed at a time.
def check_contract_lock(file):
    code = enumerate(open(file))
    key = "modifier"
    end = "}"
    length = 2;
    start = False
    first = "require"
    second = "= true"
    third = "_;"
    fourth = "= false"
    pass_one = False;
    pass_two = False;
    pass_three = False;
    pass_four = False;
    safe = False
    score = 0
    for i, line in code:
        if((start == True) and (end in line) and (len(line) <= length)):
            start = False
            if ((pass_one == True) and (pass_two == True) and (pass_three == True) and (pass_four == True)):
                safe = True
            pass_one = False;
            pass_two = False;
            pass_three = False;
            pass_four = False;
        if(key in line):
            start = True
        if ((first in line) and (pass_two == False) and (pass_three == False) and (pass_four == False)):
            pass_one = True
        if ((second in line) and (pass_one == True) and (pass_three == False) and (pass_four == False)):
            pass_two = True
        if ((third in line) and (pass_one == True) and (pass_two == True) and (pass_four == False)):
            pass_three = True
        if ((fourth in line) and (pass_one == True) and (pass_two == True) and (pass_three == True)):
            pass_four = True
    if (safe == False):            
        print("\nReentracy Bug Detected in contract")
        print("Solution: Use a blockreentracy contract lock mechanism so only a single contract function is executed")
        print("Risk: Medium\n")  
        score += 6
    return score

        
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
    score = 0
    for i, line in code:
        if ((func_name in line) and (start_char in line)):
            start = True
            line_var = i + 1
            
        if ((end_char in line) and  (start_char not in line) and (found == False)):
            start = False
            print("\nWithdraw Function Call Bug Detected at Line: " + str(line_var))
            print("Solution: We need this to check require balance and amount first")
            print("Risk: Medium\n")  
            score += 6
            
        if ((end_char in line) and  (start_char not in line) and (found == True)):
            start = False
            found = False;
            
        if ((keyword in line) and (state_var in line) and (with_amount_var in line) and (start == True)):
            if ((bigger_equals in line) or (less_equals in line)):
                found = True
    return score

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
    score = 0
    for i, line in code:
        if(((call in line) or (send in line) or (transfer in line)) and (with_amount_var in line) and (found == False)):
            call_made = True
            print("\nWithdraw Function Call Bug Detected at Line: " + str(i +1))
            print("Solution: Update state variable balance before call")
            print("Risk: High\n")  
            score += 9
          
        if ((call_made == False) and (state_var in line) and (with_amount_var in line) and (subtract in line)):
            found = True
    return score
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
    score = 0
    for i, line in code:
        if ((keyword_func in line) and (keyword_un_trust in line)):
            print("\nUntrusted Function Bug Detected at Line: " + str(i +1))
            print("Solution: Be aware that subsequent calls also inherit untrust state")
            print("Risk: low\n") 
            score += 3
        #Bad Case external call is untrusted
        if ((end in line) and (len(line) <= 2)):
            start = False
                
        if ((start == True) and (keyword_un_trust in line)):
            print("\nUntrusted Function External Call Bug Detected at Line: " + str(i +1))
            print("Solution: Be aware that subsequent calls also inherit untrust state")
            print("Risk: High\n") 
            score +=9
        if ((keyword_func in line) and (keyword in line)):
            start = True
        
        #Check Label
        if ((keyword_func in line) and (keyword_trust not in line) and (keyword_un_trust not in line)):
            print("\nUntrusted Function Bug Detected at Line: " + str(i +1))
            print("Solution: Unknown trust, label function either trusted/untrusted")
            print("Risk: Medium\n") 
            score += 6
    return score

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
    score = 0
    for i, line in code:
        #Move onto next function
        if ((end in line) and (len(line) <= 2) and (start == True)):
            #Output Phase
            #Check Missing
            if (check_found == False):
                print("\nCheck-Effect-Interaction Bug Detected at Line: " + str(function_line))
                print("Solution: Check is missing")
                print("Risk: Medium\n") 
                score += 6  
            #Check Order
            if (single_check == True):
                print("\nCheck-Effect-Interaction Bug Detected at Line: " + str(function_line))
                print("Solution: Check is out of order")
                print("Risk: Medium\n")
                score += 6  
            #Effect Order
            if ((effect_found == False) and (single_effect == False)):
                print("\nCheck-Effect-Interaction Bug Detected at Line: " + str(function_line))
                print("Solution: Effect is missing")
                print("Risk: Medium\n")  
                score += 6   
            #Effect Missing     
            if (single_effect == True):
                print("\nCheck-Effect-Interaction Bug Detected at Line: " + str(function_line))
                print("Solution: Effect is out of order")
                print("Risk: Medium\n")  
                score += 6  
            #Interact Missing
            if ((interact_found == False) and (single_interact == False)):
                print("\nCheck-Effect-Interaction Bug Detected at Line: " + str(function_line))
                print("Solution: Interact is missing")
                print("Risk: Medium\n")     
                score += 6           
            #Interact Order
            if (single_interact == True):
                print("\nCheck-Effect-Interaction Bug Detected at Line: " + str(function_line))
                print("Solution: Interact is out of order")
                print("Risk: Medium\n")      
                score += 6  
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

    return score

#Catergorise Score
def calc_score(score):
    if (score < 40):
        return 100
    if (score < 80):
        return 95
    if (score < 100):
        return 90
    if (score < 120):
        return 85
    if (score < 140):
        return 80
    if (score < 160):
        return 75
    if (score < 180):
        return 70
    if (score < 200):
        return 65
    if (score < 220):
        return 60
    if (score < 240):
        return 55
    if (score < 260):
        return 50
    if (score > 260):
        return 49

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
    file16 = "Tests/unarytest.txt"
    file17 = "Tests/dividemultiply.txt"
    file18 = "Tests/boolconst.txt"
    file19 = "Tests/arraylength.txt"
    file20 = "Tests/storageissue.txt"
    file21 = "Tests/shiftassemble.txt"
    file22 = "Tests/selfdestruct.txt"
    file23 = "Tests/lockcontract.txt"
    file24 = "Tests/lockcontractgood.txt"
    #Simple Checks
    #MAKE A FUNCTION WHICH TAKES A SINGLE FILE AND RUNS ALL THESE FUNCTIONS
    score = 0; 
    score += compiler_issue(file)
    score += check_safe_math(file2) 
    score +=check_integer_operations(file3)   
    score +=check_transfer(file4)
    score +=check_tx_origin(file5)
    score +=check_function_visibility(file6)
    score +=check_balance_equality(file7)
    score +=check_block_timestamp(file8)
    score +=check_delegate_call(file9)
    score +=check_loop_function(file10)
    score +=check_bytes(file11)
    score +=check_block_variable(file12)
    score +=check_block_number(file13)
    score +=check_block_gas(file14)
    score +=check_fallback(file15)
    score +=check_unary(file16)
    score +=check_div_multiply(file17)
    score +=check_bool_const(file18)
    score +=check_arr_length(file19)
    score +=check_init_storage_var(file20)
    score +=check_assemble_shift(file21)
    score +=check_self_destruct(file22)
    score +=check_contract_lock(file23)
    score +=check_contract_lock(file24)
    #Complex Checks
  
    # #Ask for User Input On These
    withdraw_function = "withdraw"
    balance_state_variable = "balances"
    withdraw_amount = "_amount"
    comp_file = "Tests/reentracyissue.txt"


    #CHANGE THIS TO ADD INSTRUCTIONOS FOR FUNCTION AND VARIABLE NAMES
    #Reentracy Check 2
    score+=check_withdraw_a(comp_file, withdraw_function, balance_state_variable, withdraw_amount)
    
    #Reentracy Check 1
    score+=check_withdraw_b("Tests/testret.txt", withdraw_function, balance_state_variable, withdraw_amount)
    score+=check_withdraw_b("Tests/testret1.txt", withdraw_function, balance_state_variable, withdraw_amount)

    #Reentracy Check 3
    externalfile = "Tests/externalissue.txt"
    score+=check_external_call(externalfile)
    
    # #Reentracy Check 3
    CEIfile = "Tests/checkeffectinteractissue.txt"
    score+=check_effects_interactions_pattern(CEIfile) 

    #Score Overall
    print(score)
    score = calc_score(score)
    if (score < 50):
        print("Smart Contract Score: <50%")
    else:
        print("Smart Contract Score: " + str(score) +"%" )
    
if __name__ == "__main__":
    main()