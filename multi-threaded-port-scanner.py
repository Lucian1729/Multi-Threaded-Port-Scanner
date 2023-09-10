import time
import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import threading
from threading import Thread
import socket
from queue import Queue

print_lock = threading.Lock()

# Basic parameters and initializations
# Supported modes : Light, Dark, System
ctk.set_appearance_mode("Dark")

# Supported themes : green, dark-blue, blue
ctk.set_default_color_theme("blue")

# App Class
class App(ctk.CTk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("GUI Application")
        self.geometry("500x500")
        self.port1 = 0
        self.port2 = 0
        self.thread = 50
        self.threadflag = 0
        self.customflag = 0
        self.sportflag = 0
        self.eportflag = 0
        self.scan = tk.IntVar()
        self.thread_complete = 0
        self.is_ipv6 = False
        self.rate_limiting= False # import time for sleep
        self.rate_limit_value= 50
        self.is_quick_scan= False
        self.common_ports= [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        self.displayboxflag = 0
        self.downloadflag = 0
        self.host_ip = ""

        # port 1 Entry Field
        self.dest_ip_Entry = ctk.CTkEntry(self, placeholder_text="Enter hostname or IP address: ", font=("Times", 16),width=350,height=35)
        self.dest_ip_Entry.grid(row=0, column=1, columnspan=3, padx=75, pady=(40,20), sticky="ew")

        # Radio Buttons
        self.quick = ctk.CTkRadioButton(self,text="Quick Scan",variable= self.scan, value=1, font=("Times", 16),command=self.custom)
        self.quick.grid(row=2, column=1,rowspan=1, columnspan=3, padx=(75,10), pady=(15,15), sticky="ew")
        self.quick.select()

        self.normal = ctk.CTkRadioButton(self,text="Normal Scan",variable= self.scan, value=2, font=("Times", 16),command=self.custom)
        self.normal.grid(row=4, column=1, rowspan=1, columnspan=3, padx=(75,10), pady=(15,15), sticky="ew")

        self.advance = ctk.CTkRadioButton(self,text="Advanced Scan",variable= self.scan, value=3, font=("Times", 16),command=self.custom)
        self.advance.grid(row=6, column=1, rowspan=1, columnspan=3, padx=(75,10), pady=(15,20), sticky="ew")

        # Generate Button
        self.generateResultsButton = ctk.CTkButton(self, text="Generate Results", command=self.animate_generate, font=("Times", 16),width=160,height=40)
        self.generateResultsButton.grid(row=12, column=0, columnspan=3, padx=(75,130), pady=(40,15), sticky="ew")

        # Stop Button
        self.stopButton = ctk.CTkButton(self,text="Stop", command=self.gstop, font=("Times", 16),width=140,height=40)
        self.stopButton.grid(row=12, column=2, columnspan=3, padx=(75,75), pady=(40,15), sticky="ew")

        # Clear Button
        self.clearButton = ctk.CTkButton(self,text="Clear All", command=self.clear, font=("Times", 16),width=150,height=40)
        self.clearButton.grid(row=13, column=0, columnspan=6, padx=(75,75), pady=(25,30), sticky="ew")

    def custom(self):
        self.geometry("500x500")
        if self.scan.get() == 1:
            if self.sportflag:
                self.port1_Entry.destroy()
                self.sportflag = 0
            if self.eportflag:
                self.port2_Entry.destroy()
                self.eportflag = 0
            if self.threadflag:
                self.thread_Entry.destroy()
                self.threadflag = 0
            if self.customflag:
                self.custombox.destroy()
                self.customflag = 0
            
        if self.scan.get() == 2:
            self.geometry('500x600')
            # Start Port
            if not self.sportflag:
                self.port1_Entry = ctk.CTkEntry(self, placeholder_text="Enter starting port: ", font=("Times", 16),width=350,height=40)
                self.port1_Entry.grid(row=8, column=1, columnspan=3, padx=75, pady=(10,10), sticky="ew")
                self.sportflag = 1
            # End Port
            if not self.eportflag:
                self.port2_Entry = ctk.CTkEntry(self, placeholder_text="Enter ending port: ", font=("Times", 16), width=350,height=40)
                self.port2_Entry.grid(row=9, column=1, columnspan=3, padx=75, pady=(10,10), sticky="ew")
                self.eportflag = 1
            if self.threadflag:
                self.thread_Entry.destroy()
                self.threadflag = 0
            if self.customflag:
                self.custombox.destroy()
                self.customflag = 0

        if self.scan.get() == 3:
            self.geometry("500x700")
            if not self.sportflag:
                self.port1_Entry = ctk.CTkEntry(self, placeholder_text="Enter starting port: ", font=("Times", 16),width=350,height=40)
                self.port1_Entry.grid(row=8, column=1, columnspan=3, padx=75, pady=(10,10), sticky="ew")
                self.sportflag = 1
            if not self.eportflag:
                self.port2_Entry = ctk.CTkEntry(self, placeholder_text="Enter ending port: ", font=("Times", 16), width=350,height=40)
                self.port2_Entry.grid(row=9, column=1, columnspan=3, padx=75, pady=(10,10), sticky="ew")
                self.eportflag = 1
            if not self.threadflag:
                self.threadflag = 1
                self.thread_Entry = ctk.CTkEntry(self, placeholder_text="Enter number of threads to use: (default:50) ", font=("Times", 16), width=350,height=40)
                self.thread_Entry.grid(row=10, column=1, columnspan=3, padx=75, pady=(10,10), sticky="ew")
            if not self.customflag:
                self.custombox = ctk.CTkCheckBox(self, text="Rate limitter", font=("Times", 16), command=self.check,onvalue="on", offvalue="off")
                self.custombox.grid(row=11, column=1, columnspan=3, padx=(75,0), pady=(15,10), sticky="w")
                self.customflag = 1

    def check(self):
        if self.custombox._check_state:
            self.custombox.select()
        else:
            self.custombox.selection_clear()

    def animate_generate(self):
        self.configure(relief=tk.SUNKEN)
        self.thread_complete = 0
        self.generateResultsButton.configure(state="disabled")
        animation_thread = Thread(target=self.generate_animation)
        animation_thread.daemon = True
        self.thread_stop = threading.Event()
        animation_thread.start()
        result_thread = Thread(target=self.starter)
        result_thread.start()

    def generate_animation(self):
        self.thread_stop.clear()
        frames = ["Generating.", "Generating..", "Generating..."]
        while not self.thread_stop.is_set() and self.thread_complete!=1:
            for frame in frames:
                self.generateResultsButton.configure(text=frame)
                self.generateResultsButton.update()
                time.sleep(0.5)
        if not self.thread_stop.is_set():
            self.generateResultsButton.configure(text="Generated")
        time.sleep(0.5)
        self.generateResultsButton.configure(text="Generate Results", state="normal")

    def gstop(self):
        try:
            self.thread_stop.set()
        except:
            pass

    def starter(self):
        # Text box
        if self.scan.get() == 1:
            self.geometry("1100x500")
        if self.scan.get() == 2:
            self.geometry("1100x600")
        if self.scan.get() == 3:
            self.geometry("1100x700")
            if self.custombox._check_state:
                self.rate_limiting = True
            else:
                self.rate_limiting = False            
        self.displayBox = ctk.CTkTextbox(self, width=500, height=300, font=("Times", 20),activate_scrollbars=True,fg_color="#484848")
        self.displayBox.grid(row=0, column=400, rowspan=13, padx=(10,0), pady=(40,10), sticky="nsew")
        self.displayboxflag = 1
        host = 0
        self.dest_ip = self.dest_ip_Entry.get()
        if((self.scan.get()==1 and self.dest_ip=="")):
            self.displayBox.configure(state="normal")
            self.displayBox.insert(tk.END,"Please enter the values for the fields.")
            self.thread_complete = 1
            self.displayBox.configure(state="disabled")
            return
        elif((self.scan.get()==2 or self.scan.get()==3)and (self.dest_ip=="" or self.port1_Entry.get()=="" or self.port2_Entry.get()=="")):
            self.displayBox.configure(state="normal")
            self.displayBox.insert(tk.END,"Please enter the values for the fields.")
            self.thread_complete = 1
            self.displayBox.configure(state="disabled")
            return
        if self.sportflag + self.eportflag == 2:
            if self.port1_Entry.get()!="" and self.port2_Entry.get()!="":
                try:
                    self.port1 = int(self.port1_Entry.get())
                    self.port2 = int(self.port2_Entry.get())
                    valid_ports=self.validate_ports()
                    if not valid_ports:
                        return
                except:
                    self.displayBox.configure(state="normal")
                    self.displayBox.insert(tk.END, "Please enter a valid integer value for port numbers.")
                    self.thread_complete = 1
                    self.displayBox.configure(state="disabled")
                    return
        if self.sportflag + self.eportflag == 2 and self.threadflag == 1 and self.thread_Entry.get()!="":
            try:
                self.thread = int(self.thread_Entry.get())
                if self.thread>1000:
                    self.thread=1000
                    self.displayBox.configure(state="normal")
                    self.displayBox.insert(tk.END, "Maximum threads allowed is 1000. Starting scan with 1000  threads...\n")
                    self.displayBox.configure(state="disabled")
            except:
                self.displayBox.configure(state="normal")
                self.displayBox.insert(tk.END, "Please enter a valid integer value for number of threads.")
                self.thread_complete = 1
                self.displayBox.configure(state="disabled")
                return
        elif self.threadflag==1 and self.thread_Entry.get()=="":
            self.thread = 50
        if self.is_valid_ip(self.dest_ip):
            self.host_ip = self.dest_ip
            if self.scan.get() == 1 and self.host_ip!="":
                host = 1
            if self.scan.get() == 2 or self.scan.get()==3:
                if self.port1_Entry.get()!="" and self.port2_Entry.get()!="":
                    host = 1
        else:
            try:
                self.host_ip = socket.gethostbyname(self.dest_ip)
                if self.scan.get() == 1 and self.host_ip!="":
                    host = 1
                if self.scan.get() == 2 or self.scan.get()==3:
                    if self.port1_Entry.get()!="" and self.port2_Entry.get()!="":
                        host = 1
            except socket.gaierror:
                self.displayBox.configure(state="normal")
                self.displayBox.insert(tk.END,"Hostname could not be resolved.")
                self.displayBox.configure(state="disabled")
                self.thread_complete = 1
                return
        
        #Download Button
        # Call scan_ports_threads function with input values
        if(host==1):
            self.downloadButton = ctk.CTkButton(self,text = "Download as text file",command=self.download, font=("Times", 16),width=20,height=40)
            self.downloadButton.grid(row=13, column=400, columnspan=2, padx=(5,0), pady=(20,30), sticky="ew")
            self.downloadflag = 1
            if self.threadflag == 1:
                self.scan_ports_threads()
            else:
                self.thread = 50
                self.scan_ports_threads()

    def download(self):
        try:
            header = "This is the generated file\n"
            ip = "IP Address: "+str(self.host_ip)+"\n"
            if self.scan.get()==1:
                scantype = "Scan type: Quick scan\n"
                ports = "Ports scanned: "+str(self.common_ports)+"\n"
            elif self.scan.get()==2:
                scantype = "Scan type: Normal scan\n"
                sport = "Start Port: "+str(self.port1)+"\n"
                eport = "End Port: "+str(self.port2)+"\n"
            elif self.scan.get()==3:
                scantype = "Scan type: Advanced scan\n"
                sport = "Start Port: "+str(self.port1)+"\n"
                eport = "End Port: "+str(self.port2)+"\n"
            threads = "Number of threads used: "+str(self.thread)+"\n\n"
            result = "Result Generated: \n"
            contents = self.displayBox.get("1.0", tk.END)
            file_path = filedialog.asksaveasfilename(defaultextension=".txt")
            if file_path:
                with open(file_path, "w") as f:
                    if self.scan.get()==1:
                        f.write(header+ip+scantype+ports+threads+result+contents)
                    else:
                        f.write(header+ip+scantype+sport+eport+threads+result+contents)
                    # print("File saved successfully.")
        except Exception as e:
            print("Error while saving file:", e)
    
    def clear(self):
        try:
            self.thread_stop.set()
        except:
            pass
        frames = ["Clearing.", "Clearing..", "Clearing...","Cleared"]
        for frame in frames:
            try:
                if(frame == "Clearing."):
                    if self.displayboxflag:
                        self.displayBox.destroy()
                        self.displayboxflag = 0
                    self.displayBox.destroy()
                    if self.downloadflag == 1:
                        self.downloadButton.destroy()
                        self.downloadflag = 0
                    self.thread_complete = 1
                    if self.customflag:
                        self.custombox.selection_clear()
            except:
                if self.threadflag == 1:
                    self.thread_Entry.delete(0,'end')
                continue
            self.clearButton.configure(text=frame)
            self.clearButton.update()
            if(self.dest_ip_Entry.get()!=""):
                self.dest_ip_Entry.delete(0,'end')
            if(self.sportflag==1 and self.port1_Entry.get()!=""):
                self.port1_Entry.delete(0,'end')
            if(self.eportflag==1 and self.port2_Entry.get()!=""):
                self.port2_Entry.delete(0,'end')
            if(self.threadflag==1 and self.thread_Entry.get()!=""):
                self.thread_Entry.delete(0,'end')
            time.sleep(0.2)
        self.clearButton.configure(text="Clear All",state="normal")
        if self.scan.get() == 1:
            self.geometry("500x500")
        if self.scan.get() == 2:
            self.geometry("500x600")
        if self.scan.get() == 3:
            self.geometry("500x700")
        self.thread_complete = 0

    def worker(self):
        if not self.thread_stop.is_set():
            while not self.port_queue.empty():
                port = self.port_queue.get()
                self.scan_port(port)
                if self.thread_stop.is_set():
                    return
                self.port_queue.task_done()
            self.thread_complete = 1

    def scan_port(self,port):
        #print("Host :",self.host_ip," Port: ",port)
        # self.displayBox.configure(state="normal")
        # self.displayBox.insert(tk.END,"Host: {} Port: {}\n".format(self.host_ip,port))
        # self.displayBox.configure(state="disabled")
        try:
            # Create a socket object
            s= socket.socket(socket.AF_INET6, socket.SOCK_STREAM) if self.is_ipv6 else socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # rate limiting. The rate of connection requests sent will be maximum of rate_limit_value per second
            if self.rate_limiting:
                time.sleep(self.thread/self.rate_limit_value)
            # Set timeout to 1 second
            s.settimeout(1)
            # Attempt to connect to the specified self.host_ip and port
            result= s.connect_ex((self.host_ip, port, 0, 0)) if self.is_ipv6 else s.connect_ex((self.host_ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = 'unknown'
                with print_lock:
                    self.displayBox.configure(state="normal")
                    print("Port {} is open with service ".format(port),"{}".format(service))
                    self.displayBox.insert(tk.END,"Port {} is open with service {}\n\n".format(port,service))
                    self.displayBox.configure(state="disabled")
            s.close()
        except KeyboardInterrupt:
            self.displayBox.configure(state="normal")
            self.displayBox.insert(tk.END,"Exiting program.")
            self.displayBox.configure(state="disabled")
            return
        except socket.gaierror:
            self.displayBox.configure(state="normal")
            self.displayBox.insert(tk.END,"Hostname could not be resolved. Exiting")
            self.displayBox.configure(state="disabled")
            return
        except socket.error:
            self.displayBox.configure(state="normal")
            self.displayBox.insert(tk.END,"Couldn't connect to server")
            self.displayBox.configure(state="disabled")
            return

    # Function to check if string is a valid IP address
    def is_valid_ip(self,address):
        try:
            try:
                socket.inet_aton(address)
            except socket.error:
                socket.inet_pton(socket.AF_INET6, address)
                self.is_ipv6 = True
            return True
        except socket.error:
            return False

    def validate_ports(self):
        if self.port1 < 0 or self.port1>65535:
            self.displayBox.configure(state="normal")
            self.displayBox.insert(tk.END, "Please enter the value of starting port between 0 and 65535")
            self.thread_complete = 1
            self.displayBox.configure(state="disabled")
            return 0
        if self.port2 < 0 or self.port2>65535:
            self.displayBox.configure(state="normal")
            self.displayBox.insert(tk.END, "Please enter the value of ending port between 0 and 65535")
            self.thread_complete = 1
            self.displayBox.configure(state="disabled")
            return 0
        if self.port2 < self.port1:
            self.displayBox.configure(state="normal")
            self.displayBox.insert(tk.END, "Please enter a ending port value not lesser than starting port value.")
            self.thread_complete = 1
            self.displayBox.configure(state="disabled")
            return 0
        return 1

    def scan_ports_threads(self):
        # self.displayBox.configure(state="normal")
        # self.displayBox.insert(tk.END,"Host: {} Start port: {} End Port: {} Threads: {}\n".format(self.host_ip,self.port1,self.port2,self.thread))
        # self.displayBox.configure(state="disabled")
        self.port_queue=Queue()
        print(self.thread)
        if self.scan.get()==1:
            for port in self.common_ports:
                self.port_queue.put(port)
            self.thread = len(self.common_ports)
        else:
            for port in range(self.port1, self.port2+1):
                self.port_queue.put(port)
                if self.thread> self.port2-self.port1+1:
                    self.thread= self.port2-self.port1+1
        # Split the range of ports into equal-sized chunks for each thread
        ports_per_thread = 1
        threads = []
        for i in range(self.thread):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        self.port_queue.join()

        for t in threads:
            t.join()

        self.thread_complete = 1

if __name__ == "__main__":
    app = App()
    app.mainloop()