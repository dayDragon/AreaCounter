using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using CCB.Data.Contracts;
using CCB.Data.Contracts.Repositories;
using CCB.Model.Calendars;
using CCB.Model.Documents;

namespace CCB.Services
{
    /// <summary>
    /// Сервис работы с документами
    /// </summary>
    public class CalendarService : BaseService
    {
        public CalendarService(IDataUow uow)
        {
            Contract.Requires(uow != null);
            Uow = uow;
        }

        public WorkingCalendar GetCommonCalendar(DateTime? begin = null, DateTime? end = null)
        {
            var rez = Uow.WorkingCalendars.GetCommonCalendar();
            if (rez != null)
                Uow.WorkingDays.GetAll(rez.Id, begin, end);
            return rez;
        }

        public WorkingCalendar GetCalendarForUser(Guid userId, DateTime? begin, DateTime? end)
        {
            var rez = Uow.WorkingCalendars.GetCalendarForUser(userId);
            if (rez != null)
                Uow.WorkingDays.GetAll(rez.Id, begin, end);
            return rez;
        }

        public Guid SaveCalendar(WorkingCalendar calendar)
        {
            foreach (var workingDay in calendar.WorkingDays)
                if (workingDay.Id == Guid.Empty)
                    workingDay.Id = Guid.NewGuid();

            if (calendar.Id == Guid.Empty)
                calendar.Id = Guid.NewGuid();

            if (Uow.WorkingCalendars.IsExist(calendar.Id))
                Uow.WorkingCalendars.Update(calendar);
            else
                Uow.WorkingCalendars.Add(calendar);

            return calendar.Id;
        }

        public Guid SaveShedule(Shedule shedule)
        {
            return Uow.Save<Shedule, IRepository<Shedule>>(shedule);
        }

        private Guid SaveWorkingDay(WorkingDay workingDay)
        {
            if (workingDay.Id == Guid.Empty)
                workingDay.Id = Guid.NewGuid();

            if (Uow.WorkingDays.IsExist(workingDay.Id))
                Uow.WorkingDays.Update(workingDay);
            else
                Uow.WorkingDays.Add(workingDay);
            
            return workingDay.Id;
        }

        public void DeleteWorkingDays(IEnumerable<WorkingDay> freeDays)
        {
            foreach (var day in freeDays)
            {
                Uow.WorkingDays.Delete(day);
            }

            Uow.Commit();
        }

        public DateTime? RecountShedule(Shedule shed)
        {
            //нечего пересчитывать - еще то что должно не случилось
            if (shed.NextEventTime != null && shed.NextEventTime.Value > DateTime.Now)
                return shed.NextEventTime;

            int i;
            DateTime beg;
            switch (shed.Type)
            {
                #region Single

                case SheduleTypeDictionary.Single:
                    return shed.EventTime < DateTime.Now
                                   ? (shed.NextEventTime = null)
                                   : (shed.NextEventTime = shed.EventTime);

                #endregion Single

                #region Daily

                case SheduleTypeDictionary.Daily:
                    //вышли за границы выполнения
                    if ((shed.EndDateTime != null && shed.NextEventTime != null && shed.NextEventTime > shed.EndDateTime) ||
                        (shed.CountNumber > 0 && shed.CountLeft <= 0))
                        return null;

                    //первый раз
                    if (shed.NextEventTime == null)
                    {
                        beg = shed.BeginDateTime;
                        i = 0;
                    }
                    //не первый
                    else
                    {
                        beg = shed.NextEventTime.Value;
                        i = 1;
                    }

                    if (shed.Each == 0)
                    {
                        WorkingCalendar cal = GetCommonCalendar();
                        for (; !cal.IsWorkingDay(beg.AddDays(i)); i++)
                            ;
                    }
                    else
                        i = shed.Each;

                    shed.NextEventTime = beg.AddDays(i)
                                            .Date;
                    shed.NextEventTime = shed.NextEventTime.Value.AddTicks(shed.EventTime.TimeOfDay.Ticks);
                    shed.CountLeft--;

                    //вышли за границы выполнения
                    if ((shed.EndDateTime != null && shed.NextEventTime.Value > shed.EndDateTime) ||
                        (shed.CountNumber > 0 && shed.CountLeft < 0))
                        return null;
                    break;

                #endregion Daily

                #region Weekly

                case SheduleTypeDictionary.Weekly:
                    //вышли за границы выполнения
                    if ((shed.EndDateTime != null && DateTime.Now > shed.EndDateTime) ||
                        (shed.CountNumber > 0 && shed.CountLeft <= 0) || shed.Days == 0)
                        return null;

                    //первый раз
                    if (shed.NextEventTime == null)
                    {
                        i = 0;
                        beg = shed.BeginDateTime;
                    }
                    //не первый
                    else
                    {
                        i = 1;
                        beg = shed.NextEventTime.Value;
                    }

                    //осталось дней до конца недели
                    int daysToSunday = 7 - ((int)beg.DayOfWeek + 6) % 7;
                    for (;
                            (i < daysToSunday &&
                             ((shed.Days &
                               (FlaggedWeekDays)(1 << ((int)beg.AddDays(i)
                                                                 .DayOfWeek + 6) % 7)) == 0));
                            i++)
                        ;
                    //на этой неделе нет подходящего дня
                    if (i == daysToSunday)
                    {
                        beg = beg.AddDays(7 * (shed.Each - 1) + daysToSunday);
                        i = 0;
                        //осталось дней до конца недели
                        daysToSunday = 7 - ((int)beg.DayOfWeek + 6) % 7;
                        for (;
                                (i < daysToSunday &&
                                 ((shed.Days &
                                   (FlaggedWeekDays)(1 << ((int)beg.AddDays(i)
                                                                     .DayOfWeek + 6) % 7)) == 0));
                                i++)
                            ;

                        //и на этой неделе нет подходящего дня, а это уже косяк
                        if (i == daysToSunday)
                            throw new Exception("не нашел подходящего дня для выполнения расписания");
                    }
                    shed.NextEventTime = beg.AddDays(i)
                                            .Date;
                    shed.NextEventTime = shed.NextEventTime.Value.AddTicks(shed.EventTime.TimeOfDay.Ticks);
                    shed.CountLeft--;

                    //вышли за границы выполнения
                    if ((shed.EndDateTime != null && shed.NextEventTime.Value > shed.EndDateTime) ||
                        (shed.CountNumber > 0 && shed.CountLeft < 0))
                        return null;

                    break;

                #endregion Weekly

                #region Monthly

                case SheduleTypeDictionary.Monthly:
                    //вышли за границы выполнения
                    if ((shed.EndDateTime != null && DateTime.Now > shed.EndDateTime) ||
                        (shed.CountNumber > 0 && shed.CountLeft <= 0))
                        return null;

                    //число месяца
                    if (shed.DayNumber > 0)
                    {
                        //первый раз
                        if (shed.NextEventTime == null)
                        {
                            //перекидывать на последний день если выходим за границы
                            try
                            {
                                beg = new DateTime(shed.BeginDateTime.Year,
                                                   shed.BeginDateTime.Month,
                                                   shed.DayNumber);
                            }
                            catch (ArgumentOutOfRangeException)
                            {
                                beg = new DateTime(shed.BeginDateTime.Year,
                                                   shed.BeginDateTime.Month,
                                                   1).AddMonths(1)
                                                     .AddDays(-1);
                            }
                            if (beg < shed.BeginDateTime)
                                try
                                {
                                    beg = new DateTime(shed.BeginDateTime.Year,
                                                       shed.BeginDateTime.Month,
                                                       shed.DayNumber).AddMonths(shed.Each);
                                }
                                catch (ArgumentOutOfRangeException)
                                {
                                    beg = new DateTime(shed.BeginDateTime.Year,
                                                       shed.BeginDateTime.Month,
                                                       1).AddMonths(shed.Each + 1)
                                                         .AddDays(-1);
                                }
                        }
                        //не первый
                        else
                        {
                            beg = new DateTime(shed.NextEventTime.Value.Year,
                                               shed.NextEventTime.Value.Month,
                                               shed.DayNumber);
                            if (beg < shed.NextEventTime.Value)
                                beg = new DateTime(shed.NextEventTime.Value.Year,
                                                   shed.NextEventTime.Value.Month,
                                                   shed.DayNumber).AddMonths(shed.Each);
                        }
                    }
                    //специзврат с "третьим рабочим днем"
                    else
                    {
                        WorkingCalendar cal = GetCommonCalendar();
                        //первый раз
                        if (shed.NextEventTime == null)
                        {
                            beg = ThirdWorkingDay(shed,
                                                  new DateTime(shed.BeginDateTime.Year,
                                                               shed.BeginDateTime.Month,
                                                               1),
                                                  cal);
                            if (beg < shed.BeginDateTime)
                                beg = ThirdWorkingDay(shed,
                                                      new DateTime(shed.BeginDateTime.Year,
                                                                   shed.BeginDateTime.Month,
                                                                   1).AddMonths(shed.Each),
                                                      cal);
                        }
                        //не первый
                        else
                        {
                            beg = ThirdWorkingDay(shed,
                                                  new DateTime(shed.NextEventTime.Value.Year,
                                                               shed.NextEventTime.Value.Month,
                                                               1),
                                                  cal);
                            if (beg < shed.NextEventTime.Value)
                                beg = ThirdWorkingDay(shed,
                                                      new DateTime(shed.NextEventTime.Value.Year,
                                                                   shed.NextEventTime.Value.Month,
                                                                   1).AddMonths(shed.Each),
                                                      cal);
                        }
                    }
                    shed.NextEventTime = beg;
                    shed.NextEventTime = shed.NextEventTime.Value.AddTicks(shed.EventTime.TimeOfDay.Ticks);
                    shed.CountLeft--;

                    //вышли за границы выполнения
                    if ((shed.EndDateTime != null && shed.NextEventTime.Value > shed.EndDateTime) ||
                        (shed.CountNumber > 0 && shed.CountLeft < 0))
                        return null;

                    break;

                #endregion Monthly
            }

            return shed.NextEventTime;
        }

        public DateTime ThirdWorkingDay(Shedule shed,
                                                DateTime beg,
                                                WorkingCalendar cal)
        {
            int i;
            switch (shed.SpecificDayType)
            {
                case RecurrenceSpecificDayType.anyDay:
                    if (shed.SpecificDayNumber < RecurrenceSpecificDayNumber.nextToLast)
                        beg = beg.AddDays((double)shed.SpecificDayNumber);
                    else
                    {
                        beg = new DateTime(beg.Year,
                                           beg.Month,
                                           1).AddMonths(1)
                                             .AddDays(-1);
                        if (shed.SpecificDayNumber == RecurrenceSpecificDayNumber.nextToLast)
                            beg = beg.AddDays(-1);
                    }
                    break;

                case RecurrenceSpecificDayType.weekDay:
                    if (shed.SpecificDayNumber < RecurrenceSpecificDayNumber.nextToLast)
                    {
                        var shift = (int)shed.SpecificDayNumber;
                        for (i = 0; i <= shift; i++)
                            if (!cal.IsWorkingDay(beg.AddDays(i)))
                                shift++;
                        beg = beg.AddDays(shift);
                    }
                    else
                    {
                        beg = new DateTime(beg.Year,
                                           beg.Month,
                                           1).AddMonths(1);
                        int shift = shed.SpecificDayNumber == RecurrenceSpecificDayNumber.last
                                            ? -1
                                            : -2;
                        for (i = -1; i >= shift; i--)
                            if (!cal.IsWorkingDay(beg.AddDays(i)))
                                shift--;
                        beg = beg.AddDays(shift);
                    }
                    break;

                case RecurrenceSpecificDayType.weekendDay:
                    if (shed.SpecificDayNumber < RecurrenceSpecificDayNumber.nextToLast)
                    {
                        var shift = (int)shed.SpecificDayNumber;
                        for (i = 0; i <= shift; i++)
                        {
                            if (cal.IsWorkingDay(beg.AddDays(i)))
                                shift++;
                        }
                        beg = beg.AddDays(shift);
                    }
                    else
                    {
                        beg = new DateTime(beg.Year,
                                           beg.Month,
                                           1).AddMonths(1);
                        int shift = shed.SpecificDayNumber == RecurrenceSpecificDayNumber.last
                                            ? -1
                                            : -2;
                        for (i = -1; i >= shift; i--)
                            if (cal.IsWorkingDay(beg.AddDays(i)))
                                shift--;
                        beg = beg.AddDays(shift);
                    }
                    break;

                default:

                    if (shed.SpecificDayNumber < RecurrenceSpecificDayNumber.nextToLast)
                    {
                        beg = beg.AddDays(shed.SpecificDayType - RecurrenceSpecificDayType.monday - ((int)beg.DayOfWeek + 6) % 7);
                        beg = beg.AddDays(7 * (double)shed.SpecificDayNumber);
                    }
                    else
                    {
                        beg = new DateTime(beg.Year,
                                           beg.Month,
                                           1).AddMonths(1);
                        beg = beg.AddDays(shed.SpecificDayType - RecurrenceSpecificDayType.monday - ((int)beg.DayOfWeek + 6) % 7 - 7);
                        if (shed.SpecificDayNumber == RecurrenceSpecificDayNumber.nextToLast)
                            beg = beg.AddDays(-7);
                    }
                    break;
            }
            return beg;
        }
    }
}