import { Component } from '@angular/core';
import { InteractionService } from './services/interaction.service';
import { BehaviorSubject, Observable, Subject, pipe, of } from 'rxjs';
import { map, catchError, finalize, switchMap, tap } from 'rxjs/operators';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';


@Component({
    selector: 'app-root',
    templateUrl: './app.component.html',
    styleUrls: ['./app.component.sass']
})
export class AppComponent {
    number1 = '1';
    number2 = '1';

    available$: BehaviorSubject<boolean>;
    busy$: BehaviorSubject<boolean>;

    result$ = new Observable<string>();
    error$ = new Observable<string>();
    buttonClick$ = new Subject<Event>();
    calculating$ = new BehaviorSubject<boolean>(false);

    constructor(private interactionService: InteractionService, private http: HttpClient) {
        this.available$ = interactionService.available$;
        this.error$ = interactionService.error$;
        this.busy$ = interactionService.busy$;

        let url = `${InteractionService.serviceUrl}/Calc/Add`;

        this.result$ = this.buttonClick$.pipe(
            tap(_ => this.calculating$.next(true)),
            switchMap(_ => {
                let params = `?num1=${this.number1}&num2=${this.number2}`;
                return this.http.get(encodeURI(`${url}${params}`)).pipe(
                    map(data => {
                        return JSON.stringify(data);
                    }),
                    catchError(error => {
                        console.log(error);
                        if (error instanceof HttpErrorResponse) {
                            return `There was an HTTP error: ${error.message}\r\nStatus code: ${error.status}, see console`;
                        } else {
                            return JSON.stringify(error);
                        }
                    }),
                    finalize(() => {
                        this.calculating$.next(false);
                    }),
                );
            })
        );
    }

    checkAvailability() {
        this.interactionService.check();
    }

    calculate(event: Event) {
        this.buttonClick$.next(event);
    }
}
