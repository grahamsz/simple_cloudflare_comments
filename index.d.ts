export type PluginArgs = {
    googleClientId: string,
    googleClientSecret:string,

    authCookieName:string,
    authCookieSecret: string,

}

export default function (args?: PluginArgs): PagesFunction;