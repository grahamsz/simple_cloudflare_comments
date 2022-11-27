export class SimpleCloudflareCommentsUser
{
    userId:number;
    username:string;
    authProvider:string;
    authProviderId:string;
    pictureUrl:string;  
    firstName:string;
    lastName:string;
    isAdmin : boolean;

    constructor(userId:number, username:string, authProvider:string, authProviderId:string, pictureUrl:string, firstName:string, lastName:string, isAdmin:boolean)
    {
        this.userId = userId;
        this.username = username;
        this.authProvider = authProvider;
        this.authProviderId = authProviderId;
        this.pictureUrl = pictureUrl;
        this.firstName = firstName;
        this.lastName = lastName;
        this.isAdmin = isAdmin;
    }

    async getSignedCookieString()
    {
        var u = new URLSearchParams();
        u.append("userId", this.userId.toString());
        u.append("username", this.username);    
        u.append("authProvider", this.authProvider);
        u.append("authProviderId", this.authProviderId);
        u.append("pictureUrl", this.pictureUrl);
        u.append("firstName", this.firstName);
        u.append("lastName", this.lastName);
        u.append("isAdmin", this.isAdmin.toString());

        var cookie = btoa(u.toString());

        const myDigest = await crypto.subtle.digest(
            {
              name: 'SHA-256',
            },
            new TextEncoder().encode(cookie + "9812347913284") // The data you want to hash as an ArrayBuffer
          );

          const hashArray = Array.from(new Uint8Array(myDigest));
          const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

          

          
        cookie += "|" +  hashHex;

        return cookie;
    }

    static async getFromCookieString(cookie:string)
    {
        var parts = cookie.split("|");
        var cookie = parts[0];
        var hash = parts[1];

        const myDigest = await crypto.subtle.digest(
            {
                name: 'SHA-256',
            },
            new TextEncoder().encode(cookie + "9812347913284") // The data you want to hash as an ArrayBuffer
        );
        
        const hashArray = Array.from(new Uint8Array(myDigest));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

        if(hashHex != hash)
        {
            return null;
        }

        var u = new URLSearchParams(atob(cookie));
        
        var userId = parseInt(u.get("userId"));
        var username = u.get("username");
        var authProvider = u.get("authProvider");
        var authProviderId = u.get("authProviderId");
        var pictureUrl = u.get("pictureUrl");
        var firstName = u.get("firstName");
        var lastName = u.get("lastName");
        var isAdmin = u.get("isAdmin") == "true";

        return new SimpleCloudflareCommentsUser(userId, username, authProvider, authProviderId, pictureUrl, firstName, lastName, isAdmin);

    }


}