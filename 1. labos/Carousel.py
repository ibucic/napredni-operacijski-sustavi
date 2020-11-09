import multiprocessing as mp
from time import sleep
import numpy as np

N = 8
VISITOR_NUMBER = mp.Value('i', N)


def visitor(queue, visitor_id):
    n = 3
    for i in range(n):
        time_sleep = np.random.uniform(0.1, 2.0)
        sleep(time_sleep)
        queue.put("Želim se voziti")

        while True:
            # Posjetitelj čeka poruku "Sjedi"
            message = queue.get()
            if message != "Sjedi":
                queue.put(message)
            else:
                # sleep(0.05)
                print("Sjeo posjetitelj " + str(visitor_id))
                while True:
                    # Posjetitelj čeka poruku "Ustani"
                    message = queue.get()
                    if message != "Ustani":
                        queue.put(message)
                    else:
                        sleep(0.075)
                        print("Sišao posjetitelj " + str(visitor_id) + ", još " + str(n - i - 1) + " vožnji")
                        break
                break
    print("\t---> Posjetitelj " + str(visitor_id) + " je završio\n")
    with VISITOR_NUMBER.get_lock():
        VISITOR_NUMBER.value = VISITOR_NUMBER.value - 1


def carousel(queue, maxVisitors):
    # turns = 0
    while VISITOR_NUMBER.value > 0:
        # Vrtuljak čeka poruku "Želim se voziti"
        while queue.get() != "Želim se voziti" and VISITOR_NUMBER.value != 0:
            sleep(0.075)
        carousel_working(maxVisitors=maxVisitors, queue=queue)
        # if turns == VISITOR_NUMBER.value - 2:
        #     break
        # turns += 1

    print("\nVrtuljak završio s radom\n")


# Rad vrtuljka
def carousel_working(maxVisitors, queue):
    manage_visitors(maxVisitors=maxVisitors, message="Sjedi", queue=queue)

    print("\nVrtuljak pokrenut\n\n")
    time_sleep = np.random.uniform(1.0, 3.0)
    sleep(time_sleep)
    print("\nVrtuljak zaustavljen\n\n")

    manage_visitors(maxVisitors=maxVisitors, message="Ustani", queue=queue)


# Vrtuljak šalje posjetiteljima određenu poruku
def manage_visitors(maxVisitors, message, queue):
    for i in range(maxVisitors):
        queue.put(message)
        sleep(0.05)
    sleep(1.0)


if __name__ == '__main__':
    max_visitors = 4
    list_of_visitors = list()

    q = mp.Queue()

    process_carousel = mp.Process(target=carousel,
                                  name="carousel",
                                  args=(q, max_visitors))
    process_carousel.start()

    for id_visitor in range(N):
        process_visitor = mp.Process(target=visitor,
                                     name=str(id_visitor),
                                     args=(q, id_visitor))
        process_visitor.start()
        list_of_visitors.append(process_visitor)

    for process in list_of_visitors:
        process.join()
    process_carousel.join()
