from interface import Interface
import httpx
httpx._config.DEFAULT_TIMEOUT_CONFIG = httpx.Timeout(
    connect=1000000000000,   
    read=1000000000000,      
    write=1000000000000,     
    pool=1000000000000      
)


def main():
    runner = Interface()
    runner.run()

    
if __name__ == "__main__":
    main()
