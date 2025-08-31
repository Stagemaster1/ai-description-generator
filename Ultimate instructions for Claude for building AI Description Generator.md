New instructions and general rules for interactions between Claude and human boss \- some have already been addressed in earlier chat sessions and maybe their saved backups but here it is again.

**SAFETY IS NOT NEGOTIABLE \- HIGHEST PRIORITY FOR DATA SECURITY\!\!\!\!**

I noticed a few flaws in our earlier conversations \- though it has been fun at times \- there are some serious issues that need addressing. 

I am a non technical person with 0 knowledge of anything that’s related to development environments and creating an app and utilizing it to generate income with it. I don’t know anything about **Data Safety**, I don’t know anything about how to securely set up the environment for a project like this. I noticed on several occasions that in order to fulfill my requests all risks (data security etc) were just ignored and never mentioned.  I.e. I suggested I would like to manage everything from Notion dashboard \- like sitting in the cockpit there and having access to all admin features. Never did i get a warning from you that this could be a serious security issue if users’ data / subscriber’s data was stored there and that it was safe practise to store this kind of sensitive data on an external server like **Firebase** \- where i already have an old account i forgot about for when i started on this project. I want us to use this to store the user database, but since again I don't have a clue about this platform either, I once again need step-by-step walk through with explicitly using the exact paths to where to find the necessary action buttons.  
I will involve Copilot as far as my allowed usage goes to check on our interactions and help with reasoning and code.

“Before suggesting any action, you must explicitly confirm that it introduces no new security risks, does not expose sensitive data, and does not weaken existing protections. If there is any uncertainty, pause and ask for clarification before proceeding.”

## 

|  |
| :---- |

### 

And this goes for our entire collaboration:

* **DON’T BE SYCOPHANTIC**

* **NEVER ASSUME\!\!\!**   
* **ALWAYS CONFIRM THAT YOU UNDERSTAND THE ASSIGNMENT. IF YOU NEED CLARIFICATION ON SOMETHING BEFORE YOU MAKE A SUGGESTION PLEASE ASK\!**  
* **BEFORE YOU MAKE A SUGGESTION CHECK THE WHOLE PICTURE OF THE ACTION. DOES IT CAUSE A SAFETY RISK?**  
* **DOES IT INVOLVE FUNCTIONS THAT ARE / WERE WORKING BEFORE?**   
* **COULD IT POTENTIALLY BREAK ANOTHER FUNCTION?**

“For every suggestion, provide an ‘Impact Analysis’ listing: (1) all files, functions, and systems affected, (2) possible side effects, (3) whether a backup is required, and (4) a rollback plan.”

Remember that I am still a toddler following your steps but I am fully reliable if there is a data breach or if the app crashes and leaves users with not being able to use it although they have paid for it. But still the goal is to launch this app as soon as possible without wasting time or any money. There is a strong need to earn money with this very fast. And once it proves to be fully functional without any more issues we can then first create an add-on for chrome and possibly others too and then go on create it again as a mobile app for different OS.

Always prepare the steps for me as if I was a toddler. Explain what needs to be done and why and which steps have to be taken. Check whether this ‘fix’ or ‘setup’ could influence and potentially damage our earlier work.   
If there is any risk of resetting already working features to a non-fixed state I need you to save the backup progress so if necessary we can revert this last step without touching anything else. Meaning: **I want you to always use the atomic approach**.   
**“All changes must be committed in small, descriptive commits so that only the intended change can be reverted without affecting other parts of the project.”**  
I will then review with Copilot and wait for confirmation that this is the right way to do it. After I confirm, only then give me one step at a time. Only when i confirmed i took the action give me the next step  
   
I had to learn every little step that was necessary to make this app from prompting Claude, to turning my vision of the app into a functional thing on the web. I never had to set up paypal subscriptions \- that’s why I had a hard time finding user data that was not automatically provided to our then database on netlify and admin panel. **“Before making any payment‑related changes, verify that all PayPal API keys and credentials are stored in environment variables, never in code or public repos. Confirm that all PayPal webhooks have retry logic and logging.”**  
Users possibly described before we switched paypal ID-client or maybe there was nothing set up that fetched the data from paypal and put it into our database. I don’t know how this works but we need to make absolutely sure there will not be any flaws anymore with this.  
Only when I tried to find out where the real life subscribers went did I notice the issue. I hope it was all due to the fact that they subscribed earlier than our last changes but we have to be 100% that everything works fine. I noticed in code that there is still mention of ‘sandbox’ \- perhaps that’s also a source of bugs? We are ‘live’ already after all.   
Just in case please check all webhooks and if there are missing ones that need adding to make this app fully functional \- in real time, not test mode**.“Run a full end‑to‑end test in LIVE mode (not sandbox) simulating a real transaction, from signup to payment to usage update, and confirm all data flows correctly into Firebase.”**

“When implementing new features, confirm they do not disable or alter any existing working features. If there is a risk, create a backup and test in a staging environment first.”

Another fix will be to create a login area on the page.   
My vision is that when the user gets to the page, they can try out the generator 3x(\!) \- not 5 \- and then get a request to subscribe if they want more. They can either login or create a new account. They need to sign ToS (which we still have to create) and inform them about data security. Keeping it very simple and clean. After setting up a new account they can subscribe to one of the plans (1x only\! No double entries\!) choosing monthly payments or annual payments with a minimal discount for those. Immediately after the payment process via paypal is finished they’ll be redirected to the app so they can start working on it until their usage is used up. Maybe send them a little warning message on screen when they approach their last 10 (5 for starter plan) generations so they can perhaps upgrade if needed.  
Any feedback and issues that need solving has to currently be sent to [support@soltecsol.com](mailto:support@soltecsol.com) (change footer to “Need help? Send any questions and feedback to [support@soltecsol.com](mailto:support@slltectsol.com) (in one row. Make fonts slightly bigger and bold) but eventually we need to set up chatbot or help desk guidance. But this should be simple since the app is not that complex.  

Anyway, to make it work like this we still have a long way to go.  
The user experience is supposed to be like this:

**USER enters or gets linked to my domain [soltecsol.com](http://soltecsol.com).**   
We need to set up the forwarding to netlify address (the user should not see the netlify address but still the original domain). For this I need help with the DNS setup. Also, there is currently no encryption for that domain address so I get a warning to not trust my own website. Lol got to fix that too.“Do not use HTML framing or masked redirects for the main domain. Instead, connect the domain directly to Netlify via DNS so Netlify can issue a free SSL certificate through Let’s Encrypt. Confirm HTTPS is active before launch.”

**USER CAN GENERATE FREE DESCRIPTIONS TO TEST FUNCTIONALITY**   
Usage for visitors has to be adjusted to 3 instead of 5 including the visual on the usage card and refreshing it automatically in real time. After the 5th time the User gets requested to log in or create an account ([**i.e.” I**f](http://i.e.if) **you want more please create an account with us and subscribe to a plan of your liking / needs**)  
“Ensure all usage counters update in real time via a secure connection to Firebase. No manual refresh buttons for the user — data must sync automatically.”

**USER signs up (entry in users database in firebase is created) and chooses a subscription plan. Then uses paypal to process the payment. (paypal processes payment and sends userdate either directly to Firebase if possible or via netlify(?)- i don’t know what’s possible and safe here)**  
**After confirmation that payment went through USER gets taken back to the app which loads his booked usage 50/200/unlimited \- also shown correctly on the usage progress card on top left.**  
**USER can actually use the app as intended.**  
**About 5 generations (10 for professional plan and none for enterprise) before usage approaches limit the USER gets a tiny warning banner with the suggestion (and button) to upgrade.**  
**If he does and again the whole payment process is successfully done the usage will be updated including the still left generations. So the new usage shows the total available.**   
**(There has to be a real time automatic refreshment of the data usage so it’s always showing the accurate amount. Not a button for the user to refresh it\! A constant real time connection between the admin panel and Firebase has to be set up too admin has to see what the user sees)**

**On our end we have to do the following tasks and find a way to make this user experience as described above.** 

1)  **setting up Firebase for user/ subscriber database perfectly connected with paypal webhooks being able to real time update after subscriptions or changes to the user data as well as with admin panel for temporarily access to database to potentially make those changes (i.e. give temporarily unlimited access or increase usage amount as compensation)**  
2) **Setting up DNS settings for redirecting users who enter [soltecsol.com](http://soltecsol.com) to netlify address with still showing original address (framing). Have to eliminate the warning that website is not safe\!**  
3) **Checking whether Paypal payment process really triggers creating and updating user account data. Has to work flawlessly with the mentioned creating account process before**  
     
4) **“All admin actions must be role-restricted and logged with timestamp, admin ID, and change details. No sensitive user data should be stored permanently in the admin panel — only fetched temporarily via secure queries.**  
   **”Fix Admin panel\! User data should only be fetched temporarily through live feed and not be stored there.**  
   **Features like pulling up user info through live feed and being able to make changes which after confirmation gets immediately stored in the database.**   
   **Again, I’m just expressing my wishes here. Don’t know what’s possible and if everything would still be perfectly safe \- which is a must\!**  
     
5) **“Implement a clear refund workflow that logs the reason, date, and amount refunded, and updates the user’s subscription status in Firebase immediately.”**  
   **We have to have a refund policy too for when users who paid annually in advance want to cancel before the end of the subscription period…same goes for monthly payers who have issues with the app and want to cancel. need suggestions on how to handle all this and how we can implement this into the system.**  
     
      
   **But the very first thing to do right now is to check the app database for any open keys that need to be secured \- perhaps have to replace them.** 

**“Scan the entire codebase for exposed API keys or credentials. Replace any found with environment variables and rotate them immediately.”**  
   
**Please make a comprehensive step-by-step plan with a checklist of what to build / fix in the order it has to be done to be most efficient and cause the least problems for existing functions / apps without compromising the function or safety.**  
**Use our last checklist and extract the tasks that we did not get to work on in our last session. It should be in the success\!\!- file**