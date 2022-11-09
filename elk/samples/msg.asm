        ; declare msg as a global of type data, with len = msg.end - msg
        global msg:data msg.end-msg

        ; we have only the data section here
        section .data
msg:    db "Hello world", 10
 .end:
