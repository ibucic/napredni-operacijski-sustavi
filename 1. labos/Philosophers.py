import multiprocessing as mp
from time import sleep
import numpy as np
import itertools


class Philosopher:

    def __init__(self, id_philosopher, sendPipes, receivedPipes, N):
        self.id_philosopher = id_philosopher
        self.sendPipes = sendPipes
        self.receivedPipes = receivedPipes
        self.N = N
        self.sent_request = False
        self.clock = -1
        self.request_clock = -1
        self.request = 0
        self.respond = -1
        self.request_enter = -1
        self.delayed_respond = [-1 for _ in range(N)]
        self.delayed_clock = [-1 for _ in range(N)]
        self.enter_KO = 0
        self.process = mp.Process(target=self.conference, args=(self.id_philosopher,))
        self.process.start()

    # Proces šalje svima zahtjev
    def send_requests(self):
        request = (self.id_philosopher, self.clock)
        self.respond = 0
        self.request_enter = 1
        for pipe in self.sendPipes:
            if type(pipe) is list:
                pipe[1].send(request)
        self.sent_request = True
        self.request_clock = self.clock
        print("---> Filozof {0} je poslao svima zahtjev(i, T(i)) - ({1}, {2})\n".format(self.id_philosopher, request[0],
                                                                                        request[1]))

    # Proces prima zahtjev
    # 1) sprema zahtjev - odgovara mu kad iziđe iz kritičnog odsječka
    # 2) šalje odgovor na zahtjev
    def receive_request(self, request, pipe):
        self.clock = np.maximum(self.clock, request[1]) + 1
        if self.request_enter == 1 and (
                request[1] > self.request_clock or (
                request[1] == self.request_clock and request[0] > self.id_philosopher)):
            # print("Filozof {0} sprema zahtjev(j, T(j)) - ({1}, {2})\n".format(self.id_philosopher, request[0],
            #                                                                   request[1]))
            self.delayed_respond[request[0] - 1] = 1
            self.delayed_clock[request[0] - 1] = request[1]
        else:
            self.request += 1
            respond = (self.id_philosopher, request[1])
            pipe[1].send(respond)
            print("Filozof {0} je primio zahtjev(j, T(j)) - ({1}, {2}), šalje odgovor(i, T(j)) - ({0}, {2})\n".format(
                self.id_philosopher, request[0], request[1]))

    # Proces prima odgovor na svoj zahtjev
    def receive_respond(self, respond):
        self.clock += 1
        self.respond += 1
        print(
            "Filozof {0} je primio odgovor(j, T(i)) - ({1}, {2})\n".format(self.id_philosopher, respond[0], respond[1]))
        if self.respond == (self.N - 1):
            self.enter_KO = 1
            print("$$$ Filozof {0} je primio sve odgovore - clock={1} $$$\n".format(self.id_philosopher, self.clock))

    # Proces javlja da je gotov i šalje spremljenim zahtjevima odgovor
    def send_exit(self):
        self.request_enter = 0
        for pipe in self.sendPipes:
            if type(pipe) is list:
                if self.delayed_respond[pipe[0] - 1] == 1:
                    clock = self.delayed_clock[pipe[0] - 1]
                    respond = (self.id_philosopher, clock)
                    pipe[1].send(respond)
                    self.request += 1
                    self.delayed_respond[pipe[0] - 1] = 0
                    self.delayed_clock[pipe[0] - 1] = 0
                    print("Filozof {0} šalje odgovor(i, T(j)) - ({0}, {1})\n".format(self.id_philosopher, respond[1]))
        # print("+++ Filozof {0} je poslao svima odgovore +++\n".format(self.id_philosopher))

    # Konferencija AKA Comic-Con
    def conference(self, id_philosopher):
        # ----- Participate in conference -----
        self.clock = np.random.randint(1, 10)
        print("Filozof {0}, T(i)={1}\n".format(self.id_philosopher, self.clock))
        time_sleep = np.random.uniform(0.1, 2.0)
        sleep(time_sleep)

        while True:
            # Čitaju se odgovori i zahtjevi koji dolaze procesu
            for pipe in self.receivedPipes:
                if type(pipe) is list:
                    data = pipe[1].poll()
                    if data:
                        message = pipe[1].recv()
                        if message[1] == self.request_clock:
                            self.receive_respond(message)
                        else:
                            for pipe2 in self.sendPipes:
                                if type(pipe2) is list:
                                    if message[0] == pipe2[0]:
                                        self.receive_request(message, pipe2)
            # Kritični odsječak
            if self.enter_KO:
                # print("\n**************************")
                print("*** Filozof {0} je za stolom ***".format(id_philosopher))
                sleep(3.0)
                print("*** Filozof {0} je gotov ***".format(self.id_philosopher))
                # print("**************************\n")
                self.enter_KO = 0
                self.send_exit()
            if self.sent_request is False:
                self.send_requests()
            if self.request == self.respond and self.request_enter == 0:
                break

        # ----- Participate in conference -----
        time_sleep = np.random.uniform(0.1, 2.0)
        sleep(time_sleep)
        print("\n----- Filozof {0} odlazi sa konferencije -----\n".format(id_philosopher))


if __name__ == '__main__':

    philosophers = []
    n = np.random.randint(3, 10)
    # n = 5

    communicator1 = []
    communicator2 = []

    num_philosophers = []
    for i in range(n):
        num_philosophers.append(i + 1)

    number = int((n * (n - 1)) / 2)
    for pair, _ in zip(itertools.combinations(num_philosophers, 2), [j for j in range(number)]):
        receive1, send1 = mp.Pipe(duplex=False)
        receive2, send2 = mp.Pipe(duplex=False)
        communicator1.append([pair[0], send1, pair[1], receive1])
        communicator2.append([pair[1], send2, pair[0], receive2])

    for i in range(1, n + 1):
        received_pipes = []
        send_pipes = []
        for com in communicator1:
            # Ako je prvi indeks = i (on šalje), stavi u send_pipes -> [indeks gdje šalješ, kojim pipeom]
            if com[0] == i:
                send_pipes.append([com[2], com[1]])
            # Ako je drugi indeks = i (on prima), stavi u received_pipes -> [indeks odakle primaš, kojim pipeom]
            if com[2] == i:
                received_pipes.append([com[0], com[3]])
        for com in communicator2:
            if com[0] == i:
                send_pipes.append([com[2], com[1]])
            if com[2] == i:
                received_pipes.append([com[0], com[3]])
        philosopher = Philosopher(i, send_pipes, received_pipes, n)
        philosophers.append(philosopher)
