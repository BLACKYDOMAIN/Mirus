import vt

def main():
    apikey=open("apikey.txt","r").read()
    url="http://testphp.vulnweb.com"
    with vt.Client(apikey) as client:
        try:
            print(f"Scanning URL: {url}")
            url_obj = client.get_object(f"/urls/{vt.url_id(url)}")
            item=url_obj
            total_clean = sum(item.last_analysis_stats.values())
            num_spaces = 100 - len(item.url) if len(item.url) < 100 else 10
            print(
          f'{item.url}{" " * num_spaces}'
          f'{item.last_analysis_stats["malicious"]}/{total_clean}'
            )
            print(item.last_analysis_stats)
        except KeyboardInterrupt:
            print("\nKeyboard interrupt. Closing.")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client.close()

if __name__ == "__main__":
  main()