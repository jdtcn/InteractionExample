import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { BehaviorSubject } from 'rxjs';

@Injectable()
export class InteractionService {
    private static serviceUrls: any = {
        http: 'http://127.0.0.1:40849',
        https: 'https://localhost:40850',
    };

    public static serviceUrl: string = InteractionService.serviceUrls.http;

    public available$ = new BehaviorSubject<boolean>(false);
    public busy$ = new BehaviorSubject<boolean>(true);
    public error$ = new BehaviorSubject<string>('');

    constructor(private http: HttpClient) {
        // we can check the browser to avoid unnecessary HTTP requests, it's optional
        let isIEOrEdge = typeof window !== 'undefined' && /msie\s|trident\/|edge\//i.test(window.navigator.userAgent);
        if (isIEOrEdge) {
            InteractionService.serviceUrl = InteractionService.serviceUrls.https;
        }
        this.checkAvailability();
    }

    public check() {
        InteractionService.serviceUrl = InteractionService.serviceUrls.http;
        this.checkAvailability();
    }

    private checkAvailability() {
        this.error$.next('');
        this.busy$.next(true);
        const url = `${InteractionService.serviceUrl}/Calc`;
        this.http.get<string>(url).subscribe(_ => {
            this.available$.next(true);
            console.log('InteractionService available');
        }, error => {
            if (InteractionService.serviceUrl === InteractionService.serviceUrls.http) {
                InteractionService.serviceUrl = InteractionService.serviceUrls.https;
                this.checkAvailability();
            } else {
                console.log(error);
                if (error instanceof HttpErrorResponse) {
                    this.error$.next(`There was an HTTP error: ${error.message}\r\nStatus code: ${error.status}, see console`);
                } else {
                    this.error$.next(JSON.stringify(error));
                }
                this.available$.next(false);
                this.busy$.next(false);
            }
        });
    }
}
